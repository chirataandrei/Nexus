package compliance

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"nexus-gateway/internal/keystore"
	"nexus-gateway/internal/parser"
)

type anchorEnv struct {
	dir, ledger, anchors string
	priv                 ed25519.PrivateKey
}

func newAnchorEnv(t *testing.T) *anchorEnv {
	t.Helper()
	dir := t.TempDir()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	return &anchorEnv{dir: dir, ledger: filepath.Join(dir, "ledger.jsonl"), anchors: filepath.Join(dir, "anchors.jsonl"), priv: priv}
}

func (e *anchorEnv) keys() keystore.PublicKeySet {
	k := keystore.PublicKeySet{}
	k.Add(e.priv.Public().(ed25519.PublicKey))
	return k
}

// open opens the chain with anchoring on and appends n records, then
// anchors and closes.
func (e *anchorEnv) session(t *testing.T, n int) {
	t.Helper()
	c, err := OpenChain(e.ledger, 6)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.EnableAnchoring(e.anchors, e.priv, nil, 0); err != nil {
		t.Fatalf("EnableAnchoring: %v", err)
	}
	for i := 0; i < n; i++ {
		if _, err := c.Append(Record{Event: "request_received", VerifiedAgentID: "agent-1", Reason: "r"}); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.Close(); err != nil { // Close writes the final anchor
		t.Fatal(err)
	}
}

// rewriteConsistently is the attack a bare hash chain cannot detect: edit
// a record, then recompute every prev_hash/hash after it so the chain is
// internally valid again.
func rewriteConsistently(t *testing.T, path string, mutate func(i int, r *Record)) {
	t.Helper()
	f, _ := os.Open(path)
	var recs []Record
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		var r Record
		_ = json.Unmarshal(sc.Bytes(), &r)
		recs = append(recs, r)
	}
	f.Close()
	prev := genesisHash
	var out strings.Builder
	for i := range recs {
		mutate(i, &recs[i])
		recs[i].PrevHash = prev
		recs[i].Hash = computeHash(recs[i])
		prev = recs[i].Hash
		b, _ := json.Marshal(recs[i])
		out.Write(b)
		out.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(out.String()), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestAnchors_CompleteRewriteIsDetected(t *testing.T) {
	e := newAnchorEnv(t)
	e.session(t, 10)

	if _, err := VerifyAnchors(e.ledger, e.anchors, e.keys()); err != nil {
		t.Fatalf("untouched ledger must verify: %v", err)
	}

	rewriteConsistently(t, e.ledger, func(i int, r *Record) {
		if i == 3 {
			r.Reason = "history rewritten"
		}
	})
	// The bare chain is fooled — this is the weakness anchoring fixes.
	if _, err := VerifyChain(e.ledger); err != nil {
		t.Fatalf("test setup: a consistent rewrite should pass VerifyChain, got %v", err)
	}
	if _, err := VerifyAnchors(e.ledger, e.anchors, e.keys()); err == nil {
		t.Fatal("a consistent full rewrite must be caught by the signed anchors")
	}
}

func TestAnchors_StartupRefusesRewrittenLedger(t *testing.T) {
	e := newAnchorEnv(t)
	e.session(t, 6)
	rewriteConsistently(t, e.ledger, func(i int, r *Record) { r.VerifiedAgentID = "someone-else" })

	c, err := OpenChain(e.ledger, 6)
	if err != nil {
		t.Fatalf("plain OpenChain is expected to pass: %v", err)
	}
	defer c.Close()
	if err := c.EnableAnchoring(e.anchors, e.priv, nil, 0); err == nil {
		t.Fatal("EnableAnchoring must refuse a ledger that contradicts its anchors")
	}
}

func TestAnchors_TruncationAndDeletionDetected(t *testing.T) {
	e := newAnchorEnv(t)
	e.session(t, 8)

	raw, _ := os.ReadFile(e.ledger)
	lines := strings.SplitAfter(string(raw), "\n")
	_ = os.WriteFile(e.ledger, []byte(strings.Join(lines[:5], "")), 0o600)
	if _, err := VerifyAnchors(e.ledger, e.anchors, e.keys()); err == nil {
		t.Error("truncating records covered by an anchor must be detected")
	}
	_ = os.Remove(e.ledger)
	if _, err := VerifyAnchors(e.ledger, e.anchors, e.keys()); err == nil {
		t.Error("deleting the ledger while anchors exist must be detected")
	}
}

func TestAnchors_ForgedOrRemovedAnchorsDetected(t *testing.T) {
	e := newAnchorEnv(t)
	e.session(t, 4)
	e.session(t, 4) // second run -> second anchor, linked to the first
	e.session(t, 4)

	anchors, _ := ReadAnchors(e.anchors)
	if len(anchors) != 3 {
		t.Fatalf("want 3 anchors, got %d", len(anchors))
	}

	// Attacker without the key re-signs with their own key.
	_, evil, _ := ed25519.GenerateKey(rand.Reader)
	forged := anchors[2]
	forged.Hash = "deadbeef"
	forged.Signature = ""
	raw, _ := os.ReadFile(e.anchors)
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	b, _ := json.Marshal(forged)
	_ = os.WriteFile(e.anchors, []byte(strings.Join(lines[:2], "\n")+"\n"+string(b)+"\n"), 0o600)
	if _, err := VerifyAnchors(e.ledger, e.anchors, e.keys()); err == nil {
		t.Error("an anchor with a bad signature must be rejected")
	}
	_ = evil

	// Removing the middle anchor breaks the link.
	_ = os.WriteFile(e.anchors, []byte(lines[0]+"\n"+lines[2]+"\n"), 0o600)
	if _, err := VerifyAnchors(e.ledger, e.anchors, e.keys()); err == nil {
		t.Error("removing an anchor from the middle must be detected")
	}
}

func TestAnchors_ContinueAcrossRestartAndRotation(t *testing.T) {
	e := newAnchorEnv(t)
	e.session(t, 5)
	e.session(t, 5)
	if a, err := VerifyAnchors(e.ledger, e.anchors, e.keys()); err != nil || len(a) != 2 {
		t.Fatalf("anchors=%d err=%v", len(a), err)
	}

	// Rotate: new signing key, old one kept as a retired public key.
	oldPub := e.priv.Public().(ed25519.PublicKey)
	_, e.priv, _ = ed25519.GenerateKey(rand.Reader)
	c, _ := OpenChain(e.ledger, 6)
	retired := keystore.PublicKeySet{}
	retired.Add(oldPub)
	if err := c.EnableAnchoring(e.anchors, e.priv, retired, 0); err != nil {
		t.Fatalf("rotation with retired key must work: %v", err)
	}
	_, _ = c.Append(Record{Event: "request_received"})
	_ = c.Close()

	keys := e.keys()
	keys.Add(oldPub)
	if a, err := VerifyAnchors(e.ledger, e.anchors, keys); err != nil || len(a) != 3 {
		t.Fatalf("anchors=%d err=%v", len(a), err)
	}
	if _, err := VerifyAnchors(e.ledger, e.anchors, e.keys()); err == nil {
		t.Error("without the retired key, anchors signed by it can't be verified")
	}
}

func TestAnchors_AutomaticEveryN(t *testing.T) {
	e := newAnchorEnv(t)
	c, _ := OpenChain(e.ledger, 6)
	if err := c.EnableAnchoring(e.anchors, e.priv, nil, 3); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 7; i++ {
		_, _ = c.Append(Record{Event: "x"})
	}
	anchors, _ := ReadAnchors(e.anchors)
	if len(anchors) != 2 || anchors[0].Seq != 3 || anchors[1].Seq != 6 {
		t.Errorf("anchors = %+v, want seq 3 and 6", anchors)
	}
	if err := c.Anchor(); err != nil {
		t.Fatal(err)
	}
	if err := c.Anchor(); err != nil { // idempotent when nothing is new
		t.Fatal(err)
	}
	anchors, _ = ReadAnchors(e.anchors)
	if len(anchors) != 3 || anchors[2].Seq != 7 {
		t.Errorf("anchors = %+v", anchors)
	}
	_ = c.Close()
}

func TestChain_FailedWriteLeavesNoGap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "c.jsonl")
	c, _ := OpenChain(path, 6)
	_, _ = c.Append(Record{Event: "a"})

	good := c.file
	broken, _ := os.Open(path) // read-only handle: Write fails
	c.file = broken
	if _, err := c.Append(Record{Event: "b"}); err == nil {
		t.Fatal("append on a broken file must fail")
	}
	broken.Close()
	c.file = good
	if _, err := c.Append(Record{Event: "c"}); err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if n, err := VerifyChain(path); err != nil || n != 2 {
		t.Fatalf("chain must stay valid after a failed write: n=%d err=%v", n, err)
	}
}

func TestSink_FailClosedVetoesRequestOnWriteError(t *testing.T) {
	c := newTestChain(t)
	sink := NewSink(c, nil, 100)
	meta := &parser.RequestMeta{VerifiedAgentID: "a"}

	_ = c.file.Close() // every Append now fails

	if err := sink.RecordRequestStrict(meta, "up"); err != nil {
		t.Errorf("fail-open (default) must not veto: %v", err)
	}
	sink.SetFailClosed(true)
	if err := sink.RecordRequestStrict(meta, "up"); err == nil {
		t.Error("fail-closed must veto when the record can't be written")
	}
}

func TestRevokeHandler(t *testing.T) {
	c := newTestChain(t)
	r := &fakeRevoker{}
	h := RevokeHandler(r, c)
	do := func(body string) int {
		req := httptestRequest(body)
		rec := newRecorder()
		h(rec, req)
		return rec.Code
	}
	if code := do(`{"jti":"abc"}`); code != 400 {
		t.Errorf("missing reason: %d", code)
	}
	if code := do(`{"jti":"abc","reason":"stolen","operator":"op"}`); code != 200 || !r.got["abc"] {
		t.Errorf("revoke: code=%d revoked=%v", code, r.got)
	}
	if rec := readLastRecord(t, c.path); rec.Event != "token_revoked" || rec.JTI != "abc" {
		t.Errorf("ledger record = %+v", rec)
	}
}

type fakeRevoker struct{ got map[string]bool }

func (f *fakeRevoker) Revoke(jti string) {
	if f.got == nil {
		f.got = map[string]bool{}
	}
	f.got[jti] = true
}
