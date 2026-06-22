package compliance

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func newTestChain(t *testing.T) *Chain {
	t.Helper()
	path := filepath.Join(t.TempDir(), "chain.jsonl")
	c, err := OpenChain(path, 6)
	if err != nil {
		t.Fatalf("OpenChain a eșuat: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func TestSuspendHandler_SuspendsAndLogsToChain(t *testing.T) {
	registry := NewSuspensionRegistry()
	chain := newTestChain(t)
	handler := SuspendHandler(registry, chain)

	payload, _ := json.Marshal(suspendRequest{AgentID: "agent-1", Reason: "halucinație detectată", Operator: "andrei"})
	req := httptest.NewRequest(http.MethodPost, "/nexus/control/suspend", bytes.NewReader(payload))
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if suspended, _ := registry.IsSuspended("agent-1"); !suspended {
		t.Error("agentul ar trebui suspendat după apel")
	}

	n, err := VerifyChain(chain.path)
	if err != nil || n != 1 {
		t.Errorf("suspendarea ar trebui logată în lanț: n=%d err=%v", n, err)
	}
}

func TestSuspendHandler_RejectsMissingFields(t *testing.T) {
	handler := SuspendHandler(NewSuspensionRegistry(), newTestChain(t))
	req := httptest.NewRequest(http.MethodPost, "/nexus/control/suspend", bytes.NewReader([]byte(`{"agent_id":"agent-1"}`)))
	rec := httptest.NewRecorder()
	handler(rec, req)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, vroiam 400 (reason lipsă)", rec.Code)
	}
}

func TestResumeHandler_ResumesAndLogsToChain(t *testing.T) {
	registry := NewSuspensionRegistry()
	registry.Suspend("agent-1", "motiv", "op")
	chain := newTestChain(t)
	handler := ResumeHandler(registry, chain)

	payload, _ := json.Marshal(resumeRequest{AgentID: "agent-1", Operator: "andrei"})
	req := httptest.NewRequest(http.MethodPost, "/nexus/control/resume", bytes.NewReader(payload))
	rec := httptest.NewRecorder()
	handler(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, body=%s", rec.Code, rec.Body.String())
	}
	if suspended, _ := registry.IsSuspended("agent-1"); suspended {
		t.Error("agentul nu ar trebui să mai fie suspendat")
	}
}

func TestSuspendedListHandler_ReturnsCurrentList(t *testing.T) {
	registry := NewSuspensionRegistry()
	registry.Suspend("agent-1", "m", "op")
	handler := SuspendedListHandler(registry)

	req := httptest.NewRequest(http.MethodGet, "/nexus/control/suspended", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	var list []SuspensionRecord
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatalf("JSON invalid: %v", err)
	}
	if len(list) != 1 || list[0].AgentID != "agent-1" {
		t.Errorf("listă greșită: %+v", list)
	}
}

func TestVerifyHandler_ReportsOKForFreshChain(t *testing.T) {
	chain := newTestChain(t)
	chain.Append(Record{Event: "request_received"})

	handler := VerifyHandler(chain.path)
	req := httptest.NewRequest(http.MethodGet, "/nexus/compliance/verify", nil)
	rec := httptest.NewRecorder()
	handler(rec, req)

	var resp map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("JSON invalid: %v", err)
	}
	if resp["ok"] != true {
		t.Errorf("ok = %v, vroiam true", resp["ok"])
	}
}
