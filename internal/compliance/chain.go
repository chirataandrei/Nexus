// Package compliance implements Nexus Trust Protocol's compliance
// ledger: a chain of tamper-evident records (each record contains the
// hash of the previous one, like a local mini-blockchain), written
// strictly by appending (write-once / append-only), meant to satisfy
// the traceability requirements of Article 12 of the EU AI Act.
//
// chain.go contains the core mechanism: Append, on-disk persistence,
// and VerifyChain — the integrity check an auditor, or the gateway
// itself (at startup), can run to detect any retroactive tampering with
// the history.
package compliance

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// genesisHash is the "previous hash" of the chain's first record — a
// fixed, public value with no secret meaning; its only role is to give
// every record (including the first one) a well-defined prev_hash, so
// the chain can be verified from the start.
const genesisHash = "nexus-trust-protocol-compliance-genesis-2026"

// Record is a single entry in the compliance chain.
type Record struct {
	Sequence  int64     `json:"seq"`
	Timestamp time.Time `json:"timestamp"`
	Event     string    `json:"event"` // request_received | response_returned | request_rejected | agent_suspended | agent_resumed

	// ClaimedAgentID is the (unsafe) header declared by the client;
	// VerifiedAgentID is the cryptographically confirmed identity.
	// Keeping them separate makes any discrepancy visible — a useful
	// signal for an auditor or an anomaly-detection system.
	ClaimedAgentID  string `json:"claimed_agent_id,omitempty"`
	VerifiedAgentID string `json:"verified_agent_id,omitempty"`
	TaskID          string `json:"task_id,omitempty"`
	SPIFFEID        string `json:"spiffe_id,omitempty"`
	// JTI is the unique ID of the token used (or revoked) — lets an
	// auditor tie requests to a token, and an operator revoke it.
	JTI string `json:"jti,omitempty"`

	UpstreamName string `json:"upstream_name,omitempty"`
	Tool         string `json:"tool,omitempty"` // the JSON-RPC/MCP method called, if any
	HTTPMethod   string `json:"http_method,omitempty"`
	Path         string `json:"path,omitempty"`

	// PromptSHA256 is the full request body's digest — always kept,
	// regardless of truncation, as proof of integrity. PromptExcerpt is
	// a (possibly truncated) copy of the content, useful for direct
	// human audit; PromptTruncated explicitly marks whether the excerpt
	// doesn't represent the full prompt.
	PromptSHA256     string `json:"prompt_sha256,omitempty"`
	PromptExcerpt    string `json:"prompt_excerpt,omitempty"`
	PromptTruncated  bool   `json:"prompt_truncated,omitempty"`
	PromptBytesTotal int    `json:"prompt_bytes_total,omitempty"`

	Decision   string `json:"decision,omitempty"` // allowed | rejected
	Reason     string `json:"reason,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`

	CumulativeSpendUSDToday float64 `json:"cumulative_spend_usd_today,omitempty"`

	// Operator/SuspensionReason are populated only for kill-switch events
	// (agent_suspended/agent_resumed) — see suspension.go.
	Operator         string `json:"operator,omitempty"`
	SuspensionReason string `json:"suspension_reason,omitempty"`

	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

// Chain is the compliance ledger persisted to disk.
type Chain struct {
	mu              sync.Mutex
	file            *os.File
	path            string
	lastHash        string
	seq             int64
	retentionMonths int
	anchor          *anchorer // nil until EnableAnchoring

	// Group commit. Records are written under mu (which fixes their order
	// in the chain); durability is a separate step shared by every writer
	// that is waiting at the same moment. See waitDurable.
	written  atomic.Int64 // highest seq written to the file (maybe not yet synced)
	syncMu   sync.Mutex   // guards the fields below; never held while taking mu
	syncCond *sync.Cond
	synced   int64 // highest seq known to be on disk
	syncing  bool  // a goroutine is inside file.Sync right now
	syncErr  error // first fsync failure; the chain refuses writes after it
}

// OpenChain opens (or creates) the chain file at path. If the file
// already exists, its integrity is verified BEFORE allowing new writes
// — a corrupted or retroactively modified chain makes OpenChain return
// an error, causing the gateway to refuse startup (fail-closed) instead
// of silently continuing past a compliance violation that already
// happened.
//
// retentionMonths is the declared retention policy (informational —
// stored as configuration metadata, not enforced through automatic
// deletion at this stage); the caller (config.Validate) must guarantee
// retentionMonths >= 6, per Article 12.
func OpenChain(path string, retentionMonths int) (*Chain, error) {
	if retentionMonths < 6 {
		return nil, fmt.Errorf("compliance: the minimum retention required by Article 12 is 6 months, got %d", retentionMonths)
	}

	lastSeq, lastHash, err := scanChain(path)
	if err != nil {
		return nil, fmt.Errorf("compliance: chain %s failed its startup integrity check — possible unauthorized modification: %w", path, err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("compliance: cannot open chain %s: %w", path, err)
	}

	c := &Chain{
		file:            f,
		path:            path,
		lastHash:        lastHash,
		seq:             lastSeq,
		retentionMonths: retentionMonths,
		synced:          lastSeq, // whatever was on disk at startup
	}
	c.syncCond = sync.NewCond(&c.syncMu)
	c.written.Store(lastSeq)
	return c, nil
}

// Close closes the chain's backing file.
func (c *Chain) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.anchorLocked(); err != nil { // final anchor on clean shutdown
		slog.Error("nexus.compliance.anchor_failed", "event", "anchor_failed", "error", err.Error())
	}
	return c.file.Close()
}

// RetentionMonths returns the declared retention policy.
func (c *Chain) RetentionMonths() int { return c.retentionMonths }

// Append adds a new record to the chain, automatically filling in
// Sequence, Timestamp, PrevHash, and Hash. It returns only once the
// record is durable on disk (fsync) — a compliance record reported as
// saved must actually be saved.
//
// Concurrent appends share fsyncs (group commit): each record is written
// in chain order under the lock, then every writer waiting at that moment
// is covered by a single fsync. The guarantee per call is unchanged; only
// the number of fsyncs per record drops under load.
func (c *Chain) Append(rec Record) (Record, error) {
	c.mu.Lock()

	c.syncMu.Lock()
	failed := c.syncErr
	c.syncMu.Unlock()
	if failed != nil {
		c.mu.Unlock()
		return rec, fmt.Errorf("compliance: chain %s is closed to writes after an earlier fsync failure (restart to re-verify it): %w", c.path, failed)
	}

	// seq and lastHash only advance once the record is written, so a
	// failed write leaves no gap that would later break the chain.
	rec.Sequence = c.seq + 1
	if rec.Timestamp.IsZero() {
		rec.Timestamp = time.Now().UTC()
	}
	rec.PrevHash = c.lastHash
	rec.Hash = computeHash(rec)

	line, err := json.Marshal(rec)
	if err != nil {
		c.mu.Unlock()
		return rec, fmt.Errorf("compliance: cannot serialize record: %w", err)
	}
	line = append(line, '\n')

	offset, _ := c.file.Seek(0, io.SeekEnd)
	if _, err := c.file.Write(line); err != nil {
		// A partial line would corrupt the chain; cut it off again.
		_ = c.file.Truncate(offset)
		c.mu.Unlock()
		return rec, fmt.Errorf("compliance: cannot write to chain %s: %w", c.path, err)
	}
	c.seq = rec.Sequence
	c.lastHash = rec.Hash
	c.written.Store(rec.Sequence)
	c.mu.Unlock()

	if err := c.waitDurable(rec.Sequence); err != nil {
		return rec, err
	}

	c.mu.Lock()
	due := c.anchor != nil && c.anchor.every > 0 && rec.Sequence%c.anchor.every == 0
	c.mu.Unlock()
	if due {
		if err := c.Anchor(); err != nil {
			slog.Error("nexus.compliance.anchor_failed", "event", "anchor_failed", "error", err.Error())
		}
	}
	return rec, nil
}

// waitDurable blocks until record seq is on disk. The first waiter
// becomes the leader and fsyncs everything written so far; the others
// sleep and are released when that fsync covers them. Writers that arrive
// during an fsync form the next batch.
//
// If fsync fails the records in flight may or may not be durable, and
// the chain cannot tell which, so it refuses further writes; a restart
// re-verifies the file.
func (c *Chain) waitDurable(seq int64) error {
	c.syncMu.Lock()
	defer c.syncMu.Unlock()
	for {
		if c.synced >= seq {
			return nil
		}
		if c.syncErr != nil {
			return fmt.Errorf("compliance: cannot sync chain %s to disk: %w", c.path, c.syncErr)
		}
		if c.syncing {
			c.syncCond.Wait()
			continue
		}
		c.syncing = true
		target := c.written.Load() // everything up to here is already written
		c.syncMu.Unlock()
		err := c.file.Sync()
		c.syncMu.Lock()
		c.syncing = false
		if err != nil {
			c.syncErr = err
		} else if target > c.synced {
			c.synced = target
		}
		c.syncCond.Broadcast()
	}
}

// computeHash computes a record's hash from its content (with Hash
// cleared) and the already-established PrevHash — any change to any
// field, or to its position in the chain, changes this hash.
func computeHash(rec Record) string {
	rec.Hash = ""
	b, _ := json.Marshal(rec)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// VerifyChain re-checks the integrity of an on-disk chain from the
// start, recomputing every hash and confirming the PrevHash linkage.
// Returns the number of records successfully verified; if the chain is
// broken, it returns the error along with the sequence at which the
// problem was detected.
func VerifyChain(path string) (validRecords int64, err error) {
	validRecords, _, err = scanChain(path)
	return validRecords, err
}

// scanChain is the shared implementation for OpenChain (startup check)
// and VerifyChain (on-demand check, e.g. from an admin API).
func scanChain(path string) (lastSeq int64, lastHash string, err error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, genesisHash, nil
		}
		return 0, "", fmt.Errorf("cannot read chain: %w", err)
	}
	defer f.Close()

	expectedPrev := genesisHash
	var seq int64

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			return seq, "", fmt.Errorf("unreadable record at line %d: %w", seq+1, err)
		}

		seq++
		if rec.Sequence != seq {
			return seq, "", fmt.Errorf("unexpected sequence at line %d (rec.seq=%d) — possible deletion/reordering", seq, rec.Sequence)
		}
		if rec.PrevHash != expectedPrev {
			return seq, "", fmt.Errorf("invalid prev_hash at sequence %d — the chain has been modified", seq)
		}
		want := computeHash(rec)
		if want != rec.Hash {
			return seq, "", fmt.Errorf("invalid hash at sequence %d — the record's content has been modified", seq)
		}
		expectedPrev = rec.Hash
	}
	if err := scanner.Err(); err != nil {
		return seq, "", fmt.Errorf("error reading chain: %w", err)
	}

	return seq, expectedPrev, nil
}
