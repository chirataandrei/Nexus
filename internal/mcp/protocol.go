// Package mcp contains the minimal knowledge of the Model Context
// Protocol that Nexus needs to be "natively compatible": we don't
// implement a full MCP server/client, we just recognize the standard
// MCP JSON-RPC message shapes, enough for the gateway to extract the
// exact tool name an agent is calling — information that identity
// (per-tool scopes), FinOps, and the compliance ledger can then use
// with fine granularity.
package mcp

import "encoding/json"

// The standard JSON-RPC methods from the MCP specification. The list
// isn't exhaustive (MCP also has notifications, resources, completions,
// etc.) — it's enough to distinguish an MCP message from generic
// JSON-RPC and to identify tool calls.
const (
	MethodInitialize    = "initialize"
	MethodToolsList     = "tools/list"
	MethodToolsCall     = "tools/call"
	MethodResourcesList = "resources/list"
	MethodResourcesRead = "resources/read"
	MethodPromptsList   = "prompts/list"
	MethodPromptsGet    = "prompts/get"
	MethodPing          = "ping"
)

// knownMethods is used to decide whether a generic JSON-RPC call looks
// enough like an MCP message. Any method with the "notifications/"
// prefix is also considered MCP (e.g. "notifications/initialized").
var knownMethods = map[string]bool{
	MethodInitialize:    true,
	MethodToolsList:     true,
	MethodToolsCall:     true,
	MethodResourcesList: true,
	MethodResourcesRead: true,
	MethodPromptsList:   true,
	MethodPromptsGet:    true,
	MethodPing:          true,
}

// IsMCPMethod decides whether a JSON-RPC method is part of the standard
// MCP vocabulary.
func IsMCPMethod(method string) bool {
	if knownMethods[method] {
		return true
	}
	return len(method) > len("notifications/") && method[:len("notifications/")] == "notifications/"
}

// toolCallParams is the minimal shape of the "params" field for an MCP
// "tools/call" message.
type toolCallParams struct {
	Name string `json:"name"`
}

// ExtractToolName reads the tool name from an MCP "tools/call" message.
// Returns ok=false for any other method, or if params can't be decoded
// into the expected shape.
func ExtractToolName(method string, params json.RawMessage) (string, bool) {
	if method != MethodToolsCall || len(params) == 0 {
		return "", false
	}
	var p toolCallParams
	if err := json.Unmarshal(params, &p); err != nil || p.Name == "" {
		return "", false
	}
	return p.Name, true
}
