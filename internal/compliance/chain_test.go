package compliance

import (
	"os"
	"path/filepath"
	"testing"
)

func TestOpenChain_RejectsRetentionBelowSixMonths(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chain.jsonl")
	if _, err := OpenChain(path, 5); err == nil {
		t.Error("OpenChain ar trebui să respingă o retenție sub 6 luni (Articolul 12)")
	}
}

func TestChain_AppendAndVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chain.jsonl")
	c, err := OpenChain(path, 6)
	if err != nil {
		t.Fatalf("OpenChain a eșuat: %v", err)
	}

	for i := 0; i < 5; i++ {
		if _, err := c.Append(Record{Event: "request_received", VerifiedAgentID: "agent-1"}); err != nil {
			t.Fatalf("Append a eșuat: %v", err)
		}
	}
	if err := c.Close(); err != nil {
		t.Fatalf("Close a eșuat: %v", err)
	}

	n, err := VerifyChain(path)
	if err != nil {
		t.Fatalf("VerifyChain ar trebui să accepte un lanț neschimbat: %v", err)
	}
	if n != 5 {
		t.Errorf("n = %d, vroiam 5", n)
	}
}

func TestChain_ReopenPreservesSequenceAndHash(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chain.jsonl")
	c1, err := OpenChain(path, 6)
	if err != nil {
		t.Fatalf("OpenChain a eșuat: %v", err)
	}
	rec1, err := c1.Append(Record{Event: "request_received"})
	if err != nil {
		t.Fatalf("Append a eșuat: %v", err)
	}
	c1.Close()

	c2, err := OpenChain(path, 6)
	if err != nil {
		t.Fatalf("a doua deschidere a eșuat: %v", err)
	}
	rec2, err := c2.Append(Record{Event: "response_returned"})
	if err != nil {
		t.Fatalf("Append după reopen a eșuat: %v", err)
	}
	c2.Close()

	if rec2.Sequence != rec1.Sequence+1 {
		t.Errorf("secvența nu a continuat corect: %d -> %d", rec1.Sequence, rec2.Sequence)
	}
	if rec2.PrevHash != rec1.Hash {
		t.Errorf("prev_hash al noii înregistrări ar trebui să fie hash-ul precedentei: %q != %q", rec2.PrevHash, rec1.Hash)
	}

	n, err := VerifyChain(path)
	if err != nil || n != 2 {
		t.Errorf("VerifyChain după reopen: n=%d err=%v, vroiam n=2 err=nil", n, err)
	}
}

func TestChain_DetectsTamperedContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chain.jsonl")
	c, err := OpenChain(path, 6)
	if err != nil {
		t.Fatalf("OpenChain a eșuat: %v", err)
	}
	c.Append(Record{Event: "request_received", VerifiedAgentID: "agent-1"})
	c.Append(Record{Event: "response_returned", StatusCode: 200})
	c.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("nu pot citi fișierul: %v", err)
	}
	tampered := []byte(replaceFirst(string(raw), `"status_code":200`, `"status_code":999`))
	if err := os.WriteFile(path, tampered, 0o600); err != nil {
		t.Fatalf("nu pot scrie fișierul modificat: %v", err)
	}

	if _, err := VerifyChain(path); err == nil {
		t.Error("VerifyChain ar trebui să detecteze conținutul modificat")
	}

	if _, err := OpenChain(path, 6); err == nil {
		t.Error("OpenChain ar trebui să refuze pornirea pe un lanț corupt (fail-closed)")
	}
}

func TestChain_DetectsDeletedRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "chain.jsonl")
	c, err := OpenChain(path, 6)
	if err != nil {
		t.Fatalf("OpenChain a eșuat: %v", err)
	}
	c.Append(Record{Event: "request_received"})
	c.Append(Record{Event: "response_returned"})
	c.Append(Record{Event: "request_rejected"})
	c.Close()

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("nu pot citi fișierul: %v", err)
	}
	lines := splitNonEmptyLines(string(raw))
	if len(lines) != 3 {
		t.Fatalf("ar trebui 3 linii, am găsit %d", len(lines))
	}
	// Ștergem linia din mijloc — simulează o încercare de a "uita" o cerere.
	without := lines[0] + "\n" + lines[2] + "\n"
	if err := os.WriteFile(path, []byte(without), 0o600); err != nil {
		t.Fatalf("nu pot scrie fișierul modificat: %v", err)
	}

	if _, err := VerifyChain(path); err == nil {
		t.Error("VerifyChain ar trebui să detecteze o înregistrare ștearsă din mijlocul lanțului")
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
