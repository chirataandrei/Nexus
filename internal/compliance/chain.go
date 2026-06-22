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
	"os"
	"sync"
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

	return &Chain{
		file:            f,
		path:            path,
		lastHash:        lastHash,
		seq:             lastSeq,
		retentionMonths: retentionMonths,
	}, nil
}

// Close closes the chain's backing file.
func (c *Chain) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.file.Close()
}

// RetentionMonths returns the declared retention policy.
func (c *Chain) RetentionMonths() int { return c.retentionMonths }

// Append adds a new record to the chain, automatically filling in
// Sequence, Timestamp, PrevHash, and Hash. The write is synced to disk
// (fsync) before returning — a compliance record reported as saved must
// actually be durable.
func (c *Chain) Append(rec Record) (Record, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.seq++
	rec.Sequence = c.seq
	if rec.Timestamp.IsZero() {
		rec.Timestamp = time.Now().UTC()
	}
	rec.PrevHash = c.lastHash
	rec.Hash = computeHash(rec)

	line, err := json.Marshal(rec)
	if err != nil {
		return rec, fmt.Errorf("compliance: cannot serialize record: %w", err)
	}
	line = append(line, '\n')

	if _, err := c.file.Write(line); err != nil {
		return rec, fmt.Errorf("compliance: cannot write to chain %s: %w", c.path, err)
	}
	if err := c.file.Sync(); err != nil {
		return rec, fmt.Errorf("compliance: cannot sync chain %s to disk: %w", c.path, err)
	}

	c.lastHash = rec.Hash
	return rec, nil
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
