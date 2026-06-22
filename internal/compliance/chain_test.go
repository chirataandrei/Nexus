package compliance

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenChain_RejectsRetentionBelowSixMonths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chain.jsonl")
	if _, err := OpenChain(path, 5); err == nil {
		t.Error("OpenChain should reject a retention period below 6 months (Article 12)")
	}
}

func TestChain_AppendAndVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chain.jsonl")
	c, err := OpenChain(path, 6)
	if err != nil {
		t.Fatalf("OpenChain failed: %v", err)
	}

	for i := 0; i < 5; i++ {
		if _, err := c.Append(Record{Event: "request_received", VerifiedAgentID: "agent-1"}); err != nil {
			t.Fatalf("Append failed: %v", err)
		}
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	n, err := VerifyChain(path)
	if err != nil {
		t.Fatalf("VerifyChain should accept an unmodified chain: %v", err)
	}
	if n != 5 {
		t.Errorf("n = %d, want 5", n)
	}
}

func TestChain_ReopenPreservesSequenceAndHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chain.jsonl")
	c1, err := OpenChain(path, 6)
	if err != nil {
		t.Fatalf("OpenChain failed: %v", err)
	}
	rec1, err := c1.Append(Record{Event: "request_received"})
	if err != nil {
		t.Fatalf("Append failed: %v", err)
	}
	c1.Close()

	c2, err := OpenChain(path, 6)
	if err != nil {
		t.Fatalf("second open failed: %v", err)
	}
	rec2, err := c2.Append(Record{Event: "response_returned"})
	if err != nil {
		t.Fatalf("Append after reopen failed: %v", err)
	}
	c2.Close()

	if rec2.Sequence != rec1.Sequence+1 {
		t.Errorf("sequence didn't continue correctly: %d -> %d", rec1.Sequence, rec2.Sequence)
	}
	if rec2.PrevHash != rec1.Hash {
		t.Errorf("the new record's prev_hash should be the previous record's hash: %q != %q", rec2.PrevHash, rec1.Hash)
	}

	n, err := VerifyChain(path)
	if err != nil || n != 2 {
		t.Errorf("VerifyChain after reopen: n=%d err=%v, want n=2 err=nil", n, err)
	}
}

func TestChain_DetectsTamperedContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chain.jsonl")
	c, err := OpenChain(path, 6)
	if err != nil {
		t.Fatalf("OpenChain failed: %v", err)
	}
	c.Append(Record{Event: "request_received", VerifiedAgentID: "agent-1"})
	c.Append(Record{Event: "response_returned", StatusCode: 200})
	c.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read file: %v", err)
	}
	tampered := []byte(replaceFirst(string(raw), `"status_code":200`, `"status_code":999`))
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatalf("cannot write modified file: %v", err)
	}

	if _, err := VerifyChain(path); err == nil {
		t.Error("VerifyChain should detect the modified content")
	}

	if _, err := OpenChain(path, 6); err == nil {
		t.Error("OpenChain should refuse to start on a corrupted chain (fail-closed)")
	}
}

func TestChain_DetectsDeletedRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chain.jsonl")
	c, err := OpenChain(path, 6)
	if err != nil {
		t.Fatalf("OpenChain failed: %v", err)
	}
	c.Append(Record{Event: "request_received"})
	c.Append(Record{Event: "response_returned"})
	c.Append(Record{Event: "request_rejected"})
	c.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read file: %v", err)
	}
	lines := splitNonEmptyLines(string(raw))
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines, found %d", len(lines))
	}
	// Delete the middle line — simulates an attempt to "forget" a request.
	without := lines[0] + "\n" + lines[2] + "\n"
	if err := os.WriteFile(path, []byte(without), 0o600); err != nil {
		t.Fatalf("cannot write modified file: %v", err)
	}

	if _, err := VerifyChain(path); err == nil {
		t.Error("VerifyChain should detect a record deleted from the middle of the chain")
	}
}

func replaceFirst(s, old, new string) string {
	idx := indexOf(s, old)
	if idx < 0 {
		return s
	}
	return s[:idx] + new + s[idx+len(old):]
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func splitNonEmptyLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			if i > start {
				out = append(out, s[start:i])
			}
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}
