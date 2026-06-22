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
		t.Fatalf("Parse a returnat eroare neașteptată: %v", err)
	}
	if meta.Protocol != ProtocolREST {
		t.Errorf("protocol = %q, vroiam %q", meta.Protocol, ProtocolREST)
	}
	if meta.AgentID != "agent-123" {
		t.Errorf("agent_id = %q, vroiam %q", meta.AgentID, "agent-123")
	}
	if len(body) != 0 {
		t.Errorf("body ar trebui gol pentru un GET fără corp, am primit %d bytes", len(body))
	}
}

func TestParse_JSONRPCRequest_GenericNonMCPMethod(t *testing.T) {
	payload := `{"jsonrpc":"2.0","method":"math/add","id":"42","params":{"a":1,"b":2}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/internal/rpc", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	meta, body, err := Parse(req)
	if err != nil {
		t.Fatalf("Parse a returnat eroare neașteptată: %v", err)
	}
	if meta.Protocol != ProtocolJSONRPC {
		t.Fatalf("protocol = %q, vroiam %q", meta.Protocol, ProtocolJSONRPC)
	}
	if meta.JSONRPCMethod != "math/add" {
		t.Errorf("jsonrpc_method = %q, vroiam %q", meta.JSONRPCMethod, "math/add")
	}
	if meta.MCPTool != "" {
		t.Errorf("o metodă JSON-RPC generică nu ar trebui să populeze mcp_tool, am primit %q", meta.MCPTool)
	}
	if string(body) != payload {
		t.Errorf("body ar trebui păstrat intact pentru proxy, am primit: %s", body)
	}
}

func TestParse_MCPToolsCall_DetectedAsMCPWithToolName(t *testing.T) {
	payload := `{"jsonrpc":"2.0","method":"tools/call","id":"42","params":{"name":"read_email"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/internal/mcp", strings.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")

	meta, body, err := Parse(req)
	if err != nil {
		t.Fatalf("Parse a returnat eroare neașteptată: %v", err)
	}
	if meta.Protocol != ProtocolMCP {
		t.Fatalf("protocol = %q, vroiam %q", meta.Protocol, ProtocolMCP)
	}
	if meta.JSONRPCMethod != "tools/call" {
		t.Errorf("jsonrpc_method = %q, vroiam %q", meta.JSONRPCMethod, "tools/call")
	}
	if meta.MCPTool != "read_email" {
		t.Errorf("mcp_tool = %q, vroiam %q", meta.MCPTool, "read_email")
	}
	if string(body) != payload {
		t.Errorf("body ar trebui păstrat intact pentru proxy, am primit: %s", body)
	}
}

func TestParse_MCPToolsList_DetectedAsMCPWithoutToolName(t *testing.T) {
	payload := `{"jsonrpc":"2.0","method":"tools/list","id":"1"}`
	req := httptest.NewRequest(http.MethodPost, "/v1/internal/mcp", strings.NewReader(payload))

	meta, _, err := Parse(req)
	if err != nil {
		t.Fatalf("Parse a returnat eroare neașteptată: %v", err)
	}
	if meta.Protocol != ProtocolMCP {
		t.Errorf("protocol = %q, vroiam %q", meta.Protocol, ProtocolMCP)
	}
	if meta.MCPTool != "" {
		t.Errorf("tools/list nu ar trebui să populeze mcp_tool, am primit %q", meta.MCPTool)
	}
}

func TestParse_RedactsSensitiveHeaders(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/v1/openai/models", nil)
	req.Header.Set("Authorization", "Bearer super-secret-token")

	meta, _, err := Parse(req)
	if err != nil {
		t.Fatalf("Parse a returnat eroare neașteptată: %v", err)
	}
	if got := meta.Headers["Authorization"]; got != "[REDACTED]" {
		t.Errorf("Authorization ar trebui mascat, am primit: %q", got)
	}
}

func TestParse_MalformedJSONIsTreatedAsREST(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/v1/openai/chat", strings.NewReader(`{not-json`))

	meta, _, err := Parse(req)
	if err != nil {
		t.Fatalf("Parse a returnat eroare neașteptată: %v", err)
	}
	if meta.Protocol != ProtocolREST {
		t.Errorf("JSON malformat ar trebui tratat ca REST, am primit %q", meta.Protocol)
	}
}
