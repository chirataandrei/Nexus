package parser

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestParse_RESTRequest(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/openai/models", nil)
	req.Header.Set("X-Nexus-Agent-Id", "agent-123")

	meta, body, err := Parse(req)
	if err != nil {
		t.Fatalf("Parse returned an unexpected error: %v", err)
	}
	if meta.Protocol != ProtocolREST {
		t.Errorf("protocol = %q, want %q", meta.Protocol, ProtocolREST)
	}
	if meta.AgentID != "agent-123" {
		t.Errorf("agent_id = %q, want %q", meta.AgentID, "agent-123")
	}
	if len(body) != 0 {
		t.Errorf("body should be empty for a GET with no body, got %d bytes", len(body))
	}
}

func TestParse_JSONRPCRequest_GenericNonMCPMethod(t *testing.T) {
	payload := `{"jsonrpc":"2.0","method":"math/add","id":"42","params":{"a":1,"b":2}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/internal/rpc", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	meta, body, err := Parse(req)
	if err != nil {
		t.Fatalf("Parse returned an unexpected error: %v", err)
	}
	if meta.Protocol != ProtocolJSONRPC {
		t.Fatalf("protocol = %q, want %q", meta.Protocol, ProtocolJSONRPC)
	}
	if meta.JSONRPCMethod != "math/add" {
		t.Errorf("jsonrpc_method = %q, want %q", meta.JSONRPCMethod, "math/add")
	}
	if meta.MCPTool != "" {
		t.Errorf("a generic JSON-RPC method should not populate mcp_tool, got %q", meta.MCPTool)
	}
	if string(body) != payload {
		t.Errorf("body should be kept intact for the proxy, got: %s", body)
	}
}

func TestParse_MCPToolsCall_DetectedAsMCPWithToolName(t *testing.T) {
	payload := `{"jsonrpc":"2.0","method":"tools/call","id":"42","params":{"name":"read_email"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/internal/mcp", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	meta, body, err := Parse(req)
	if err != nil {
		t.Fatalf("Parse returned an unexpected error: %v", err)
	}
	if meta.Protocol != ProtocolMCP {
		t.Fatalf("protocol = %q, want %q", meta.Protocol, ProtocolMCP)
	}
	if meta.JSONRPCMethod != "tools/call" {
		t.Errorf("jsonrpc_method = %q, want %q", meta.JSONRPCMethod, "tools/call")
	}
	if meta.MCPTool != "read_email" {
		t.Errorf("mcp_tool = %q, want %q", meta.MCPTool, "read_email")
	}
	if string(body) != payload {
		t.Errorf("body should be kept intact for the proxy, got: %s", body)
	}
}

func TestParse_MCPToolsList_DetectedAsMCPWithoutToolName(t *testing.T) {
	payload := `{"jsonrpc":"2.0","method":"tools/list","id":"1"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/internal/mcp", strings.NewReader(payload))

	meta, _, err := Parse(req)
	if err != nil {
		t.Fatalf("Parse returned an unexpected error: %v", err)
	}
	if meta.Protocol != ProtocolMCP {
		t.Errorf("protocol = %q, want %q", meta.Protocol, ProtocolMCP)
	}
	if meta.MCPTool != "" {
		t.Errorf("tools/list should not populate mcp_tool, got %q", meta.MCPTool)
	}
}

func TestParse_RedactsSensitiveHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/openai/models", nil)
	req.Header.Set("Authorization", "Bearer super-secret-token")

	meta, _, err := Parse(req)
	if err != nil {
		t.Fatalf("Parse returned an unexpected error: %v", err)
	}
	if got := meta.Headers["Authorization"]; got != "[REDACTED]" {
		t.Errorf("Authorization should be redacted, got: %q", got)
	}
}

func TestParse_MalformedJSONIsTreatedAsREST(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/openai/chat", strings.NewReader(`{not-json`))

	meta, _, err := Parse(req)
	if err != nil {
		t.Fatalf("Parse returned an unexpected error: %v", err)
	}
	if meta.Protocol != ProtocolREST {
		t.Errorf("malformed JSON should be treated as REST, got %q", meta.Protocol)
	}
}

func TestParse_JSONRPCBatchIsFlagged(t *testing.T) {
	payload := `[{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"read_email"}},` +
		`{"jsonrpc":"2.0","method":"tools/call","id":2,"params":{"name":"delete_email"}}]`
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("  "+payload))

	meta, _, err := Parse(req)
	if err != nil {
		t.Fatalf("Parse returned an unexpected error: %v", err)
	}
	if !meta.IsBatch {
		t.Error("a JSON-RPC batch must set IsBatch")
	}
	if meta.MCPTool != "" {
		t.Errorf("MCPTool = %q, want empty for a batch", meta.MCPTool)
	}
}

func TestParse_PlainJSONArrayIsNotABatch(t *testing.T) {
	for _, payload := range []string{`[1,2,3]`, `[{"a":1}]`, `[]`, `[not json`} {
		req := httptest.NewRequest(http.MethodPost, "/x", strings.NewReader(payload))
		meta, _, err := Parse(req)
		if err != nil {
			t.Fatalf("Parse(%s) error: %v", payload, err)
		}
		if meta.IsBatch {
			t.Errorf("%s must not be flagged as a JSON-RPC batch", payload)
		}
	}
}
