// Package parser extracts structured metadata from the HTTP requests
// flowing through the gateway: method, path, relevant headers, and, if
// the payload is JSON-RPC (as used by many agent/MCP protocols), the
// RPC method and the parameters being called. This metadata is the
// foundation for compliance logging and for identity/budget decisions.
package parser

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"nexus-gateway/internal/mcp"
)

// Protocol identifies the kind of payload detected in the request body.
type Protocol string

const (
	ProtocolREST    Protocol = "REST"
	ProtocolJSONRPC Protocol = "JSON-RPC"
	// ProtocolMCP marks a JSON-RPC message that explicitly uses the
	// standard Model Context Protocol vocabulary (e.g. "tools/call",
	// "resources/read") — a more precise subcategory of generic
	// JSON-RPC, recognized natively by the gateway.
	ProtocolMCP     Protocol = "MCP"
	ProtocolUnknown Protocol = "UNKNOWN"
)

// MaxInspectedBody limits how many bytes we read to determine the
// protocol and extract metadata, so we don't hold huge payloads in
// memory just for inspection. The full body is still forwarded to the
// upstream untouched.
const MaxInspectedBody = 1 << 20 // 1 MiB

// jsonRPCEnvelope is the minimal shape of a JSON-RPC 2.0 request, used
// frequently by agent/tool-calling protocols (including MCP).
type jsonRPCEnvelope struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	ID      json.RawMessage `json:"id,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// RequestMeta is the result of parsing a request: everything Nexus
// needs for routing, validation, logging, and identity/budget
// enforcement.
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
	// AgentID is populated from the X-Nexus-Agent-Id header — a plain
	// claim made by the client, NOT cryptographically verified. The
	// trusted identity lives in the Verified* fields below, populated by
	// SPIFFEValidator only after a successful signature check. AgentID
	// stays useful for debugging/correlation, not for authorization
	// decisions.
	AgentID string `json:"agent_id,omitempty"`

	// UpstreamName and RequiredScope are populated by the proxy package
	// once the route has been identified, before validation — so the
	// identity/budget hooks (Validator, BudgetEnforcer) know which
	// upstream the request targets and what scope is required, without
	// their interfaces needing extra parameters.
	UpstreamName  string `json:"upstream_name,omitempty"`
	RequiredScope string `json:"required_scope,omitempty"`

	// MCPTool is the exact name of the MCP tool being called, extracted
	// from params.name of a "tools/call" message. Populated only for MCP
	// requests — enables scope policies and logging at the granularity
	// of a single tool (e.g. "read email" vs. "delete email"), not just
	// the whole upstream.
	MCPTool string `json:"mcp_tool,omitempty"`

	// IsBatch is true when the body is a JSON-RPC batch (an array of
	// messages). Per-tool scope decisions are made from a single parsed
	// message, so a batch would be authorized with the upstream's generic
	// scope while the upstream executes every call in it. The proxy
	// rejects batches instead of guessing.
	IsBatch bool `json:"is_batch,omitempty"`

	// The fields below are populated exclusively by a Validator
	// (identity.SPIFFEValidator) after a successful cryptographic
	// verification of the JWT-SVID presented by the agent. They are the
	// request's real, trusted identity — the ones used for audit/
	// compliance and for budget decisions.
	SPIFFEID        string   `json:"spiffe_id,omitempty"`
	VerifiedAgentID string   `json:"verified_agent_id,omitempty"`
	VerifiedTaskID  string   `json:"verified_task_id,omitempty"`
	VerifiedScopes  []string `json:"verified_scopes,omitempty"`
	// VerifiedJTI is the token's unique ID — what an operator needs to
	// revoke a specific stolen token.
	VerifiedJTI string `json:"verified_jti,omitempty"`

	// BudgetReservedUSD is the in-flight cost reserved for this request
	// by the BudgetEnforcer; released by proxy.BudgetReleaser.
	BudgetReservedUSD float64 `json:"-"`

	// RequestBody is the full request body (the agent's "prompt"),
	// populated by Parse and used by compliance.Sink to compute an
	// integrity digest and, optionally, a truncated excerpt in the
	// compliance chain. Deliberately excluded from JSON (json:"-") so it
	// doesn't show up in operational stdout logs — only the compliance
	// sink, built explicitly for that, reads it directly from the
	// struct.
	RequestBody []byte `json:"-"`
}

// relevantHeaders are the headers we copy uncensored into RequestMeta.
// Any header that may carry secrets (Authorization, Cookie, API keys)
// is excluded here and handled separately, masked.
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

// Parse reads the HTTP request, extracts the metadata, and returns the
// original (unaltered) body so the caller can reconstruct r.Body to
// forward it intact to the upstream.
func Parse(r *http.Request) (*RequestMeta, []byte, error) {
	body, err := readLimited(r.Body, MaxInspectedBody)
	if err != nil {
		return nil, nil, err
	}
	// Restore r.Body in full (including any untruncated remainder) so
	// the proxy can send the complete payload to the upstream.
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
	} else if isJSONRPCBatch(body) {
		meta.Protocol = ProtocolJSONRPC
		meta.IsBatch = true
	} else if len(body) == 0 {
		meta.Protocol = ProtocolREST
	}

	return meta, body, nil
}

// tryParseJSONRPC attempts to decode body as JSON-RPC 2.0. Returns
// ok=false if body isn't valid JSON or doesn't contain the "jsonrpc"
// field.
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

// isJSONRPCBatch reports whether body is a JSON array containing at
// least one JSON-RPC message (an object with a "jsonrpc" field). Plain
// JSON arrays that aren't JSON-RPC are not batches.
func isJSONRPCBatch(body []byte) bool {
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 || trimmed[0] != '[' {
		return false
	}
	var items []json.RawMessage
	if err := json.Unmarshal(trimmed, &items); err != nil {
		return false
	}
	for _, it := range items {
		var probe struct {
			JSONRPC *json.RawMessage `json:"jsonrpc"`
		}
		if json.Unmarshal(it, &probe) == nil && probe.JSONRPC != nil {
			return true
		}
	}
	return false
}

// readLimited reads the entire request body (without truncating it —
// the full payload must be forwarded to the upstream), but avoids
// unnecessary allocations for requests without a body.
func readLimited(r io.Reader, _ int64) ([]byte, error) {
	if r == nil {
		return nil, nil
	}
	return io.ReadAll(r)
}
