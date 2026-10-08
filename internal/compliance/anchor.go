// anchor.go makes the ledger resistant to a full rewrite.
//
// A bare hash chain proves records weren't edited *relative to each
// other*, but whoever can write the file can recompute every hash from
// the edit onward and the chain still verifies. Anchoring closes that: at
// intervals the head of the chain (sequence + hash) is signed with an
// Ed25519 key and appended to a separate anchors file (ideally on another
// volume or shipped elsewhere — each anchor is also logged on stdout).
// Rewriting history now changes hashes the signed anchors pin down, and
// forging new anchors needs the anchor key, which is not in the ledger.
//
// What it does NOT cover: records appended after the last anchor (the
// exposure window is the anchor interval), and an attacker who holds the
// anchor key or can delete the anchors file together with the ledger.
// See docs/THREAT_MODEL.md.
package compliance

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"time"

	"nexus-gateway/internal/keystore"
)

// Anchor is a signed commitment to the ledger's head at a point in time.
type Anchor struct {
	Seq       int64     `json:"seq"`
	Hash      string    `json:"head_hash"`
	Timestamp time.Time `json:"timestamp"`
	// PrevAnchor is the SHA-256 of the previous anchor's signed message
	// (genesisHash for the first), so anchors can't be removed from the
	// middle of the file unnoticed.
	PrevAnchor string `json:"prev_anchor"`
	KID        string `json:"kid"`
	Signature  string `json:"signature"` // base64 Ed25519 over message()
}

func (a Anchor) message() []byte {
	return []byte(fmt.Sprintf("nexus-anchor-v1|%d|%s|%s|%s|%s",
		a.Seq, a.Hash, a.Timestamp.UTC().Format(time.RFC3339Nano), a.PrevAnchor, a.KID))
}

func (a Anchor) digest() string {
	sum := sha256.Sum256(a.message())
	return hex.EncodeToString(sum[:])
}

type anchorer struct {
	path       string
	priv       ed25519.PrivateKey
	kid        string
	every      int64
	lastSeq    int64
	prevDigest string
}

// EnableAnchoring turns on signed anchors for this chain. It first
// verifies the existing anchors file against the ledger (using the
// current key plus any retired public keys) and refuses to proceed if
// they disagree — the ledger was rewritten or truncated since the last
// run. every is the number of records between automatic anchors (0 =
// only on Anchor/Close, e.g. from a timer).
func (c *Chain) EnableAnchoring(anchorPath string, priv ed25519.PrivateKey, retired keystore.PublicKeySet, every int) error {
	keys := keystore.PublicKeySet{}
	for k, v := range retired {
		keys[k] = v
	}
	keys.Add(priv.Public().(ed25519.PublicKey))

	anchors, err := VerifyAnchors(c.path, anchorPath, keys)
	if err != nil {
		return fmt.Errorf("compliance: anchor check failed — the ledger no longer matches its signed anchors: %w", err)
	}
	a := &anchorer{
		path:       anchorPath,
		priv:       priv,
		kid:        keystore.KeyID(priv.Public().(ed25519.PublicKey)),
		every:      int64(every),
		prevDigest: genesisHash,
	}
	if n := len(anchors); n > 0 {
		a.lastSeq = anchors[n-1].Seq
		a.prevDigest = anchors[n-1].digest()
	}
	c.mu.Lock()
	c.anchor = a
	c.mu.Unlock()
	return nil
}

// Anchor signs and stores the current head if records were appended
// since the last anchor. Safe to call from a timer.
func (c *Chain) Anchor() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.anchorLocked()
}

func (c *Chain) anchorLocked() error {
	a := c.anchor
	if a == nil || c.seq == 0 || c.seq == a.lastSeq {
		return nil
	}
	// An anchor must never vouch for records that are not on disk yet.
	if err := c.file.Sync(); err != nil {
		return fmt.Errorf("compliance: cannot sync ledger before anchoring: %w", err)
	}
	an := Anchor{Seq: c.seq, Hash: c.lastHash, Timestamp: time.Now().UTC(), PrevAnchor: a.prevDigest, KID: a.kid}
	an.Signature = base64.StdEncoding.EncodeToString(ed25519.Sign(a.priv, an.message()))

	line, err := json.Marshal(an)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(a.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("compliance: cannot open anchors file: %w", err)
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return fmt.Errorf("compliance: cannot write anchor: %w", err)
	}
	if err := f.Sync(); err != nil {
		return fmt.Errorf("compliance: cannot sync anchor: %w", err)
	}

	a.lastSeq, a.prevDigest = an.Seq, an.digest()
	// Also leave a copy in the operational log stream, which is usually
	// shipped off-box: a second place an attacker would have to rewrite.
	slog.Info("nexus.compliance.anchor", "event", "ledger_anchored", "seq", an.Seq, "head_hash", an.Hash, "kid", an.KID)
	return nil
}

// ReadAnchors parses an anchors file. A missing file yields no anchors.
func ReadAnchors(path string) ([]Anchor, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []Anchor
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var a Anchor
		if err := json.Unmarshal(sc.Bytes(), &a); err != nil {
			return nil, fmt.Errorf("unreadable anchor at line %d: %w", len(out)+1, err)
		}
		out = append(out, a)
	}
	return out, sc.Err()
}

// VerifyAnchors checks every anchor in anchorPath: its signature (by
// kid, against keys), its link to the previous anchor, and that the
// ledger at path has exactly the anchored hash at the anchored sequence.
// It returns the verified anchors.
func VerifyAnchors(ledgerPath, anchorPath string, keys keystore.PublicKeySet) ([]Anchor, error) {
	anchors, err := ReadAnchors(anchorPath)
	if err != nil {
		return nil, err
	}
	if len(anchors) == 0 {
		return nil, nil
	}

	prev := genesisHash
	var lastSeq int64
	want := make(map[int64]string, len(anchors))
	for i, a := range anchors {
		pub, ok := keys[a.KID]
		if !ok {
			return nil, fmt.Errorf("anchor %d is signed by unknown key %q", i+1, a.KID)
		}
		sig, err := base64.StdEncoding.DecodeString(a.Signature)
		if err != nil || !ed25519.Verify(pub, a.message(), sig) {
			return nil, fmt.Errorf("anchor %d (seq %d) has an invalid signature", i+1, a.Seq)
		}
		if a.PrevAnchor != prev {
			return nil, fmt.Errorf("anchor %d (seq %d) does not link to the previous anchor — an anchor was removed or reordered", i+1, a.Seq)
		}
		if a.Seq <= lastSeq {
			return nil, fmt.Errorf("anchor %d has non-increasing sequence %d", i+1, a.Seq)
		}
		prev, lastSeq = a.digest(), a.Seq
		want[a.Seq] = a.Hash
	}

	f, err := os.Open(ledgerPath)
	if err != nil {
		return nil, fmt.Errorf("anchors exist up to seq %d but the ledger cannot be read: %w", lastSeq, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	var seq int64
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var rec struct {
			Hash string `json:"hash"`
		}
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			return nil, fmt.Errorf("unreadable ledger record at line %d: %w", seq+1, err)
		}
		seq++
		if h, ok := want[seq]; ok {
			if h != rec.Hash {
				return nil, fmt.Errorf("ledger record %d does not match its signed anchor — history was rewritten", seq)
			}
			delete(want, seq)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	if len(want) > 0 {
		return nil, fmt.Errorf("ledger has %d records but was anchored up to seq %d — records were truncated", seq, lastSeq)
	}
	return anchors, nil
}
