package compliance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"nexus-gateway/internal/parser"
)

func readLastRecord(t *testing.T, path string) Record {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("cannot read chain: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	var rec Record
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &rec); err != nil {
		t.Fatalf("the last line isn't valid JSON: %v", err)
	}
	return rec
}

func TestSink_RecordRequest_HashesPromptAndStoresExcerpt(t *testing.T) {
	chain := newTestChain(t)
	sink := NewSink(chain, nil, 4096)

	body := []byte(`{"jsonrpc":"2.0","method":"tools/call","params":{"name":"send_email"}}`)
	meta := &parser.RequestMeta{
		VerifiedAgentID: "agent-1",
		VerifiedTaskID:  "task-1",
		JSONRPCMethod:   "tools/call",
		RequestBody:     body,
	}
	sink.RecordRequest(meta, "internal-tools")

	rec := readLastRecord(t, chain.path)
	wantSum := sha256.Sum256(body)
	if rec.PromptSHA256 != hex.EncodeToString(wantSum[:]) {
		t.Errorf("incorrect prompt_sha256")
	}
	if rec.PromptExcerpt != string(body) {
		t.Errorf("prompt_excerpt = %q, want %q", rec.PromptExcerpt, body)
	}
	if rec.PromptTruncated {
		t.Error("should not be truncated for a small body")
	}
	if rec.Tool != "tools/call" {
		t.Errorf("tool = %q", rec.Tool)
	}
}

func TestSink_TruncatesLargePrompts(t *testing.T) {
	chain := newTestChain(t)
	sink := NewSink(chain, nil, 10) // deliberately small limit

	body := []byte("0123456789ABCDEFGHIJ") // 20 bytes > 10
	meta := &parser.RequestMeta{VerifiedAgentID: "agent-1", RequestBody: body}
	sink.RecordRequest(meta, "mock")

	rec := readLastRecord(t, chain.path)
	if !rec.PromptTruncated {
		t.Error("should be marked as truncated")
	}
	if rec.PromptExcerpt != "0123456789" {
		t.Errorf("prompt_excerpt = %q", rec.PromptExcerpt)
	}
	if rec.PromptBytesTotal != 20 {
		t.Errorf("prompt_bytes_total = %d, want 20", rec.PromptBytesTotal)
	}
	// The digest must remain that of the FULL body, not the excerpt.
	wantSum := sha256.Sum256(body)
	if rec.PromptSHA256 != hex.EncodeToString(wantSum[:]) {
		t.Error("prompt_sha256 should be computed over the full body, not the excerpt")
	}
}

func TestSink_RecordResponse_AttachesDecisionAndCost(t *testing.T) {
	chain := newTestChain(t)
	costLookup := func(agentID, taskID string) (float64, bool) {
		if agentID == "agent-1" {
			return 1.23, true
		}
		return 0, false
	}
	sink := NewSink(chain, costLookup, 4096)

	meta := &parser.RequestMeta{VerifiedAgentID: "agent-1", VerifiedTaskID: "task-1"}
	sink.RecordResponse(meta, "openai", 200, 42)

	rec := readLastRecord(t, chain.path)
	if rec.Decision != "allowed" {
		t.Errorf("decision = %q, want allowed", rec.Decision)
	}
	if rec.CumulativeSpendUSDToday != 1.23 {
		t.Errorf("cumulative_spend_usd_today = %v, want 1.23", rec.CumulativeSpendUSDToday)
	}
	if rec.StatusCode != 200 || rec.DurationMS != 42 {
		t.Errorf("incorrect status/duration: %+v", rec)
	}
}

func TestSink_RecordResponse_MarksRejectedStatusesCorrectly(t *testing.T) {
	chain := newTestChain(t)
	sink := NewSink(chain, nil, 4096)

	sink.RecordResponse(&parser.RequestMeta{}, "openai", 502, 5)
	rec := readLastRecord(t, chain.path)
	if rec.Decision != "rejected" {
		t.Errorf("a 502 status should be marked 'rejected', got %q", rec.Decision)
	}
}

func TestSink_RecordRejection_IncludesReason(t *testing.T) {
	chain := newTestChain(t)
	sink := NewSink(chain, nil, 4096)

	sink.RecordRejection(&parser.RequestMeta{AgentID: "claimed-agent"}, "identity_validation_failed: token expired")

	rec := readLastRecord(t, chain.path)
	if rec.Decision != "rejected" || rec.Reason != "identity_validation_failed: token expired" {
		t.Errorf("incorrect rejection: %+v", rec)
	}
}
