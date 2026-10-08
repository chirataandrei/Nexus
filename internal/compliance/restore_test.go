package compliance

import (
	"path/filepath"
	"testing"
	"time"
)

type fakeRestorer struct{ got map[string]time.Time }

func (f *fakeRestorer) RestoreRevoked(jti string, at time.Time) { f.got[jti] = at }

// A suspension written before a "restart" must be active after replaying
// the ledger into a brand-new registry.
func TestRestoreState_SuspensionSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	c, err := OpenChain(path, 6)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []Record{
		{Event: "agent_suspended", VerifiedAgentID: "a1", SuspensionReason: "bad", Operator: "op"},
		{Event: "agent_suspended", VerifiedAgentID: "a2", SuspensionReason: "also bad"},
		{Event: "agent_resumed", VerifiedAgentID: "a2"},
		{Event: "request_received", VerifiedAgentID: "a3"},
		{Event: "token_revoked", JTI: "jti-1", SuspensionReason: "stolen"},
	} {
		if _, err := c.Append(r); err != nil {
			t.Fatal(err)
		}
	}
	c.Close()

	// "Restart": fresh registries, same ledger.
	reg := NewSuspensionRegistry()
	rev := &fakeRestorer{got: map[string]time.Time{}}
	sum, err := RestoreState(path, reg, rev)
	if err != nil {
		t.Fatal(err)
	}
	if ok, reason := reg.IsSuspended("a1"); !ok || reason != "bad" {
		t.Errorf("a1 should be suspended with its reason, got %v %q", ok, reason)
	}
	if ok, _ := reg.IsSuspended("a2"); ok {
		t.Error("a2 was resumed; it must not come back suspended")
	}
	if ok, _ := reg.IsSuspended("a3"); ok {
		t.Error("a3 was never suspended")
	}
	if _, ok := rev.got["jti-1"]; !ok {
		t.Error("jti-1 revocation was not restored")
	}
	if sum.Suspended != 1 || sum.Revoked != 1 {
		t.Errorf("summary = %+v", sum)
	}
}

func TestRestoreState_MissingLedgerIsEmpty(t *testing.T) {
	reg := NewSuspensionRegistry()
	sum, err := RestoreState(filepath.Join(t.TempDir(), "none.jsonl"), reg, nil)
	if err != nil || sum.Suspended != 0 {
		t.Fatalf("sum=%+v err=%v", sum, err)
	}
}

// The full path through the HTTP handler: suspend, "restart", still suspended.
func TestSuspendHandler_PersistsAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ledger.jsonl")
	c, err := OpenChain(path, 6)
	if err != nil {
		t.Fatal(err)
	}
	reg := NewSuspensionRegistry()
	rr := newRecorder()
	SuspendHandler(reg, c).ServeHTTP(rr, httptestRequest(`{"agent_id":"evil","reason":"exfiltration"}`))
	if rr.Code != 200 {
		t.Fatalf("suspend = %d %s", rr.Code, rr.Body.String())
	}
	c.Close()

	c2, err := OpenChain(path, 6) // restart: chain is re-verified
	if err != nil {
		t.Fatal(err)
	}
	defer c2.Close()
	reg2 := NewSuspensionRegistry()
	if _, err := RestoreState(path, reg2, nil); err != nil {
		t.Fatal(err)
	}
	if ok, _ := reg2.IsSuspended("evil"); !ok {
		t.Fatal("the suspended agent could request tokens again after a restart")
	}
}
