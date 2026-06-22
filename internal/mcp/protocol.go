// Package mcp conține cunoștințele minime despre Model Context Protocol
// de care Nexus are nevoie pentru a fi "nativ compatibil": nu implementăm
// un server/client MCP complet, ci doar recunoaștem formele standard de
// mesaje JSON-RPC ale MCP, suficient cât gateway-ul să poată extrage
// exact numele instrumentului (tool) apelat de un agent — informație pe
// care identitatea (scope per-tool), FinOps și registrul de conformitate
// o pot folosi în continuare cu granularitate fină.
package mcp

import "encoding/json"

// Metodele JSON-RPC standard din specificația MCP. Lista nu este
// exhaustivă (MCP mai are notificări, resurse, completări etc.) — este
// suficientă pentru a distinge un mesaj MCP de un JSON-RPC generic și
// pentru a identifica apelurile de instrumente.
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

// knownMethods este folosit pentru a decide dacă un JSON-RPC generic
// arată suficient ca un mesaj MCP. Orice metodă cu prefix "notifications/"
// este de asemenea considerată MCP (ex. "notifications/initialized").
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

// IsMCPMethod decide dacă o metodă JSON-RPC face parte din vocabularul
// standard MCP.
func IsMCPMethod(method string) bool {
	if knownMethods[method] {
		return true
	}
	return len(method) > len("notifications/") && method[:len("notifications/")] == "notifications/"
}

// toolCallParams este forma minimă a câmpului "params" pentru un mesaj
// MCP "tools/call".
type toolCallParams struct {
	Name string `json:"name"`
}

// ExtractToolName citește numele instrumentului dintr-un mesaj MCP
// "tools/call". Returnează ok=false pentru orice altă metodă sau dacă
// params nu se poate decoda în forma așteptată.
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
