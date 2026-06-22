package mcp

import "testing"

func TestIsMCPMethod_KnownMethods(t *testing.T) {
	for _, m := range []string{MethodInitialize, MethodToolsList, MethodToolsCall, MethodResourcesList, MethodResourcesRead, MethodPromptsList, MethodPromptsGet, MethodPing} {
		if !IsMCPMethod(m) {
			t.Errorf("IsMCPMethod(%q) = false, want true", m)
		}
	}
}

func TestIsMCPMethod_Notifications(t *testing.T) {
	if !IsMCPMethod("notifications/initialized") {
		t.Error("a method with the notifications/ prefix should be recognized as MCP")
	}
}

func TestIsMCPMethod_UnknownMethod(t *testing.T) {
	if IsMCPMethod("something/unknown") {
		t.Error("an unknown method should not be recognized as MCP")
	}
}

func TestExtractToolName_ValidToolsCall(t *testing.T) {
	name, ok := ExtractToolName(MethodToolsCall, []byte(`{"name":"send_email","arguments":{"to":"x@y.com"}}`))
	if !ok || name != "send_email" {
		t.Fatalf("name=%q ok=%v, want send_email/true", name, ok)
	}
}

func TestExtractToolName_WrongMethod(t *testing.T) {
	if _, ok := ExtractToolName(MethodToolsList, []byte(`{"name":"send_email"}`)); ok {
		t.Error("ExtractToolName should return ok=false for a method other than tools/call")
	}
}

func TestExtractToolName_MissingName(t *testing.T) {
	if _, ok := ExtractToolName(MethodToolsCall, []byte(`{"arguments":{}}`)); ok {
		t.Error("ExtractToolName should return ok=false without the name field")
	}
}

func TestExtractToolName_EmptyParams(t *testing.T) {
	if _, ok := ExtractToolName(MethodToolsCall, nil); ok {
		t.Error("ExtractToolName should return ok=false for empty params")
	}
}
