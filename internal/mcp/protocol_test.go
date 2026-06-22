package mcp

import "testing"

func TestIsMCPMethod_KnownMethods(t *testing.T) {
	for _, m := range []string{MethodInitialize, MethodToolsList, MethodToolsCall, MethodResourcesList, MethodResourcesRead, MethodPromptsList, MethodPromptsGet, MethodPing} {
		if !IsMCPMethod(m) {
			t.Errorf("IsMCPMethod(%q) = false, vroiam true", m)
		}
	}
}

func TestIsMCPMethod_Notifications(t *testing.T) {
	if !IsMCPMethod("notifications/initialized") {
		t.Error("o metodă cu prefix notifications/ ar trebui recunoscută ca MCP")
	}
}

func TestIsMCPMethod_UnknownMethod(t *testing.T) {
	if IsMCPMethod("ceva/necunoscut") {
		t.Error("o metodă necunoscută nu ar trebui recunoscută ca MCP")
	}
}

func TestExtractToolName_ValidToolsCall(t *testing.T) {
	name, ok := ExtractToolName(MethodToolsCall, []byte(`{"name":"send_email","arguments":{"to":"x@y.com"}}`))
	if !ok || name != "send_email" {
		t.Fatalf("name=%q ok=%v, vroiam send_email/true", name, ok)
	}
}

func TestExtractToolName_WrongMethod(t *testing.T) {
	if _, ok := ExtractToolName(MethodToolsList, []byte(`{"name":"send_email"}`)); ok {
		t.Error("ExtractToolName ar trebui să returneze ok=false pentru altă metodă decât tools/call")
	}
}

func TestExtractToolName_MissingName(t *testing.T) {
	if _, ok := ExtractToolName(MethodToolsCall, []byte(`{"arguments":{}}`)); ok {
		t.Error("ExtractToolName ar trebui să returneze ok=false fără câmpul name")
	}
}

func TestExtractToolName_EmptyParams(t *testing.T) {
	if _, ok := ExtractToolName(MethodToolsCall, nil); ok {
		t.Error("ExtractToolName ar trebui să returneze ok=false pentru params gol")
	}
}
