package compliance

import "testing"

func TestSuspensionRegistry_SuspendAndCheck(t *testing.T) {
	r := NewSuspensionRegistry()

	if suspended, _ := r.IsSuspended("agent-1"); suspended {
		t.Fatal("agent-1 nu ar trebui suspendat inițial")
	}

	r.Suspend("agent-1", "comportament anormal", "operator@nexus")

	suspended, reason := r.IsSuspended("agent-1")
	if !suspended {
		t.Fatal("agent-1 ar trebui suspendat după Suspend")
	}
	if reason != "comportament anormal" {
		t.Errorf("reason = %q", reason)
	}
}

func TestSuspensionRegistry_Resume(t *testing.T) {
	r := NewSuspensionRegistry()
	r.Suspend("agent-1", "motiv", "op")

	if ok := r.Resume("agent-1"); !ok {
		t.Error("Resume ar trebui să returneze true pentru un agent suspendat")
	}
	if suspended, _ := r.IsSuspended("agent-1"); suspended {
		t.Error("agent-1 nu ar trebui să mai fie suspendat după Resume")
	}
	if ok := r.Resume("agent-necunoscut"); ok {
		t.Error("Resume pe un agent nesuspendat ar trebui să returneze false")
	}
}

func TestSuspensionRegistry_List(t *testing.T) {
	r := NewSuspensionRegistry()
	r.Suspend("agent-1", "m1", "op")
	r.Suspend("agent-2", "m2", "op")

	list := r.List()
	if len(list) != 2 {
		t.Fatalf("len(list) = %d, vroiam 2", len(list))
	}
}
