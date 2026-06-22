package finops

import (
	"context"
	"testing"

	"nexus-gateway/internal/parser"
)

func TestRecorder_RecordsCostFromOpenAIResponse(t *testing.T) {
	ledger := NewLedger()
	r := NewRecorder(ledger)

	meta := &parser.RequestMeta{VerifiedAgentID: "agent-1", VerifiedTaskID: "task-1"}
	body := []byte(`{"usage":{"prompt_tokens":1000,"completion_tokens":1000,"total_tokens":2000}}`)

	r.RecordSpend(context.Background(), meta, "openai", 0.01, body) // $0.01 / 1000 tokens

	snap := snapshotFor(t, ledger, "agent-1")
	if snap.SpentUSD != 0.02 {
		t.Errorf("spentUSD = %v, want 0.02 (2000 tokens * $0.01/1000)", snap.SpentUSD)
	}
	if snap.TaskTokens["task-1"] != 2000 {
		t.Errorf("task_tokens = %v, want 2000", snap.TaskTokens["task-1"])
	}
}

func TestRecorder_IgnoresResponsesWithoutUsage(t *testing.T) {
	ledger := NewLedger()
	r := NewRecorder(ledger)

	meta := &parser.RequestMeta{VerifiedAgentID: "agent-1", VerifiedTaskID: "task-1"}
	r.RecordSpend(context.Background(), meta, "internal-tools", 0, []byte(`{"result":"ok"}`))

	if len(ledger.Snapshot()) != 0 {
		t.Error("no consumption should be recorded for a response without a usage field")
	}
}

func TestRecorder_IgnoresUnverifiedRequests(t *testing.T) {
	ledger := NewLedger()
	r := NewRecorder(ledger)

	meta := &parser.RequestMeta{} // no VerifiedAgentID
	r.RecordSpend(context.Background(), meta, "openai", 0.01, []byte(`{"usage":{"total_tokens":1000}}`))

	if len(ledger.Snapshot()) != 0 {
		t.Error("no consumption should be recorded for a request without a verified identity")
	}
}

func TestRecorder_ZeroPriceMeansZeroCostButStillTracksTokens(t *testing.T) {
	ledger := NewLedger()
	r := NewRecorder(ledger)

	meta := &parser.RequestMeta{VerifiedAgentID: "agent-1", VerifiedTaskID: "task-1"}
	r.RecordSpend(context.Background(), meta, "internal-llm", 0, []byte(`{"usage":{"total_tokens":500}}`))

	snap := snapshotFor(t, ledger, "agent-1")
	if snap.SpentUSD != 0 {
		t.Errorf("with price 0, the cost should be 0, got %v", snap.SpentUSD)
	}
	if snap.TaskTokens["task-1"] != 500 {
		t.Errorf("tokens should be tracked even with price 0, got %v", snap.TaskTokens["task-1"])
	}
}
