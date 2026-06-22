// Package parser extrage metadate structurate din cererile HTTP care trec
// prin gateway: metodă, path, anteturi relevante și, dacă payload-ul este
// JSON-RPC (cum folosesc multe protocoale de agenți/MCP), metoda RPC și
// parametrii apelați. Aceste metadate sunt baza pentru jurnalizarea de
// conformitate și pentru deciziile de identitate/buget.
package parser

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"nexus-gateway/internal/mcp"
)

// Protocol identifică tipul de payload detectat în corpul cererii.
type Protocol string

const (
	ProtocolREST    Protocol = "REST"
	ProtocolJSONRPC Protocol = "JSON-RPC"
	// ProtocolMCP marchează un mesaj JSON-RPC care folosește explicit
	// vocabularul standard Model Context Protocol (ex. "tools/call",
	// "resources/read") — o sub-categorie mai precisă a JSON-RPC generic,
	// recunoscută nativ de gateway.
	ProtocolMCP     Protocol = "MCP"
	ProtocolUnknown Protocol = "UNKNOWN"
)

// MaxInspectedBody limitează câți bytes citim pentru a determina protocolul
// și a extrage metadate, ca să nu ținem în memorie payload-uri uriașe doar
// pentru inspecție. Corpul integral este în continuare transmis upstream-ului.
const MaxInspectedBody = 1 << 20 // 1 MiB

// jsonRPCEnvelope este forma minimă a unui request JSON-RPC 2.0, folosită
// frecvent de protocoale de tip agent/tool-calling (inclusiv MCP).
type jsonRPCEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	ID      json.RawMessage `json:"id,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// RequestMeta este rezultatul parsării unei cereri: tot ce are nevoie
// Nexus pentru rutare, validare, logging și enforcement de identitate și
// buget.
type RequestMeta struct {
	Timestamp     time.Time         `json:"timestamp"`
	Method        string            `json:"http_method"`
	Path          string            `json:"path"`
	RemoteAddr    string            `json:"remote_addr"`
	Protocol      Protocol          `json:"protocol"`
	JSONRPCMethod string            `json:"jsonrpc_method,omitempty"`
	JSONRPCID     string            `json:"jsonrpc_id,omitempty"`
	ContentLength int64             `json:"content_length"`
	Headers       map[string]string `json:"headers"`
	// AgentID este populat din antetul X-Nexus-Agent-Id — o simplă
	// declarație a clientului, NEVERIFICATĂ criptografic. Identitatea de
	// încredere este cea din câmpurile Verified* de mai jos, populate de
	// SPIFFEValidator doar după o verificare de semnătură reușită. AgentID
	// rămâne util pentru depanare/corelare, nu pentru decizii de
	// autorizare.
	AgentID string `json:"agent_id,omitempty"`

	// UpstreamName și RequiredScope sunt populate de pachetul proxy după
	// ce ruta a fost identificată, înainte de validare — astfel hook-urile
	// de identitate/buget (Validator, BudgetEnforcer) știu către ce
	// upstream se face cererea și ce scope este necesar, fără ca
	// interfața lor să trebuiască extinsă cu parametri suplimentari.
	UpstreamName  string `json:"upstream_name,omitempty"`
	RequiredScope string `json:"required_scope,omitempty"`

	// MCPTool este numele exact al instrumentului MCP apelat, extras din
	// params.name al unui mesaj "tools/call". Populat doar pentru cereri
	// MCP — permite politici de scope și jurnalizare la granularitatea
	// unui singur instrument (ex. "citește email" vs. "șterge email"),
	// nu doar a upstream-ului întreg.
	MCPTool string `json:"mcp_tool,omitempty"`

	// Câmpurile de mai jos sunt populate exclusiv de un Validator
	// (identity.SPIFFEValidator) după o verificare criptografică reușită
	// a JWT-SVID-ului prezentat de agent. Sunt identitatea de încredere
	// reală a cererii — cele folosite în audit/conformitate și în
	// deciziile de buget.
	SPIFFEID        string   `json:"spiffe_id,omitempty"`
	VerifiedAgentID string   `json:"verified_agent_id,omitempty"`
	VerifiedTaskID  string   `json:"verified_task_id,omitempty"`
	VerifiedScopes  []string `json:"verified_scopes,omitempty"`

	// RequestBody este corpul integral al cererii ("promptul" agentului),
	// populat de Parse și folosit de compliance.Sink pentru a calcula un
	// digest de integritate și, opțional, un extras trunchiat în lanțul
	// de conformitate. Exclus deliberat din JSON
	// (json:"-") ca să nu apară în logurile operaționale de pe stdout —
	// doar sink-ul de conformitate, construit explicit pentru asta, îl
	// citește direct din struct.
	RequestBody []byte `json:"-"`
}

// relevantHeaders sunt anteturile pe care le copiem necenzurate în
// RequestMeta. Orice antet care poate conține secrete (Authorization,
// Cookie, chei API) este exclus de aici și gestionat separat, mascat.
var relevantHeaders = []string{
	"Content-Type",
	"User-Agent",
	"X-Nexus-Agent-Id",
	"X-Nexus-Task-Id",
	"X-Request-Id",
}

var sensitiveHeaders = []string{
	"Authorization",
	"X-Api-Key",
	"Cookie",
}

// Parse citește cererea HTTP, extrage metadatele și returnează corpul
// original (nealterat) astfel încât apelantul să poată reconstrui
// r.Body pentru a-l trimite intact către upstream.
func Parse(r *http.Request) (*RequestMeta, []byte, error) {
	body, err := readLimited(r.Body, MaxInspectedBody)
	if err != nil {
		return nil, nil, err
	}
	// Restaurăm r.Body integral (inclusiv eventualul rest netăiat) pentru
	// ca proxy-ul să poată trimite payload-ul complet către upstream.
	r.Body = io.NopCloser(bytes.NewReader(body))

	meta := &RequestMeta{
		Timestamp:     time.Now().UTC(),
		Method:        r.Method,
		Path:          r.URL.Path,
		RemoteAddr:    r.RemoteAddr,
		ContentLength: r.ContentLength,
		Headers:       map[string]string{},
		Protocol:      ProtocolREST,
		RequestBody:   body,
	}

	for _, h := range relevantHeaders {
		if v := r.Header.Get(h); v != "" {
			meta.Headers[h] = v
		}
	}
	for _, h := range sensitiveHeaders {
		if r.Header.Get(h) != "" {
			meta.Headers[h] = "[REDACTED]"
		}
	}
	meta.AgentID = r.Header.Get("X-Nexus-Agent-Id")

	if env, ok := tryParseJSONRPC(body); ok {
		meta.Protocol = ProtocolJSONRPC
		meta.JSONRPCMethod = env.Method
		meta.JSONRPCID = string(env.ID)

		if mcp.IsMCPMethod(env.Method) {
			meta.Protocol = ProtocolMCP
			if toolName, ok := mcp.ExtractToolName(env.Method, env.Params); ok {
				meta.MCPTool = toolName
			}
		}
	} else if len(body) == 0 {
		meta.Protocol = ProtocolREST
	}

	return meta, body, nil
}

// tryParseJSONRPC încearcă să decodeze body ca JSON-RPC 2.0. Returnează
// ok=false dacă body nu este JSON valid sau nu conține câmpul "jsonrpc".
func tryParseJSONRPC(body []byte) (jsonRPCEnvelope, bool) {
	var env jsonRPCEnvelope
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return env, false
	}
	if err := json.Unmarshal(trimmed, &env); err != nil {
		return env, false
	}
	if env.JSONRPC == "" || env.Method == "" {
		return env, false
	}
	return env, true
}

// readLimited citește tot corpul cererii (fără a-l trunchia — payload-ul
// complet trebuie transmis upstream-ului), dar evită alocări inutile
// pentru cereri fără corp.
func readLimited(r io.Reader, _ int64) ([]byte, error) {
	if r == nil {
		return nil, nil
	}
	return io.ReadAll(r)
}
