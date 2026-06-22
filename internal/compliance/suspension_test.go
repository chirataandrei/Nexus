package compliance

import "testing"

func TestSuspensionRegistry_SuspendAndCheck(t *testing.T) {
	r := NewSuspensionRegistry()

	if suspended, _ := r.IsSuspended("agent-1"); suspended {
		t.Fatal("agent-1 should not be suspended initially")
	}

	r.Suspend("agent-1", "abnormal behavior", "operator@nexus")

	suspended, reason := r.IsSuspended("agent-1")
	if !suspended {
		t.Fatal("agent-1 should be suspended after Suspend")
	}
	if reason != "abnormal behavior" {
		t.Errorf("reason = %q", reason)
	}
}

func TestSuspensionRegistry_Resume(t *testing.T) {
	r := NewSuspensionRegistry()
	r.Suspend("agent-1", "reason", "op")

	if ok := r.Resume("agent-1"); !ok {
		t.Error("Resume should return true for a suspended agent")
	}
	if suspended, _ := r.IsSuspended("agent-1"); suspended {
		t.Error("agent-1 should no longer be suspended after Resume")
	}
	if ok := r.Resume("unknown-agent"); ok {
		t.Error("Resume on a non-suspended agent should return false")
	}
}

func TestSuspensionRegistry_List(t *testing.T) {
	r := NewSuspensionRegistry()
	r.Suspend("agent-1", "m1", "op")
	r.Suspend("agent-2", "m2", "op")

	list := r.List()
	if len(list) != 2 {
		t.Fatalf("len(list) = %d, want 2", len(list))
	}
}
