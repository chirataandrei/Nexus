// sink.go connects the compliance chain to the gateway's request flow:
// it implements logging.AuditSink (the same interface used by
// StdoutLogger) so every request processed by the proxy is, in
// parallel, also written to the tamper-evident ledger — with no
// changes to the main loop in internal/proxy.
package compliance

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"unicode/utf8"

	"nexus-gateway/internal/parser"
)

// CostLookup is a function that returns an agent/task's cumulative
// spend for today, if known. The compliance sink doesn't import the
// finops package — the caller (main.go) supplies a function built on
// top of the FinOps ledger, keeping the packages independent.
type CostLookup func(agentID, taskID string) (spentUSDToday float64, ok bool)

// Sink is the logging.AuditSink implementation that writes to Chain.
type Sink struct {
	chain           *Chain
	costLookup      CostLookup
	maxExcerptBytes int
	failClosed      bool
}

// SetFailClosed controls what happens when a request's audit record
// can't be written: false (default) logs the error and lets the request
// through (availability over completeness); true makes
// RecordRequestStrict fail, so the proxy refuses the request with 503
// (completeness over availability — no un-audited calls).
func (s *Sink) SetFailClosed(v bool) { s.failClosed = v }

// NewSink builds a Sink. maxExcerptBytes controls how much of the
// request body is copied as readable text into the chain (the SHA-256
// digest is always full, regardless of this limit). costLookup may be
// nil, in which case the cumulative cost field is simply omitted.
func NewSink(chain *Chain, costLookup CostLookup, maxExcerptBytes int) *Sink {
	if maxExcerptBytes <= 0 {
		maxExcerptBytes = 4096
	}
	return &Sink{chain: chain, costLookup: costLookup, maxExcerptBytes: maxExcerptBytes}
}

// RecordRequest implements logging.AuditSink.
func (s *Sink) RecordRequest(meta *parser.RequestMeta, upstream string) {
	_ = s.RecordRequestStrict(meta, upstream)
}

// RecordRequestStrict implements logging.StrictRequestRecorder. It
// returns an error only if the write failed and the sink is fail-closed.
func (s *Sink) RecordRequestStrict(meta *parser.RequestMeta, upstream string) error {
	rec := s.baseRecord("request_received", meta, upstream)
	if err := s.append(rec); err != nil && s.failClosed {
		return err
	}
	return nil
}

// RecordResponse implements logging.AuditSink.
func (s *Sink) RecordResponse(meta *parser.RequestMeta, upstream string, statusCode int, durationMS int64) {
	rec := s.baseRecord("response_returned", meta, upstream)
	rec.Decision = decisionForStatus(statusCode)
	rec.StatusCode = statusCode
	rec.DurationMS = durationMS
	if s.costLookup != nil {
		if spent, ok := s.costLookup(meta.VerifiedAgentID, meta.VerifiedTaskID); ok {
			rec.CumulativeSpendUSDToday = spent
		}
	}
	_ = s.append(rec)
}

// RecordRejection implements logging.AuditSink.
func (s *Sink) RecordRejection(meta *parser.RequestMeta, reason string) {
	rec := s.baseRecord("request_rejected", meta, meta.UpstreamName)
	rec.Decision = "rejected"
	rec.Reason = reason
	_ = s.append(rec)
}

// baseRecord builds the fields shared by every event type, based on the
// request's metadata — including the prompt's digest/excerpt.
func (s *Sink) baseRecord(event string, meta *parser.RequestMeta, upstream string) Record {
	// Tool prefers the exact MCP tool name, more precise than the generic
	// JSON-RPC method "tools/call" — an auditor sees directly
	// "send_email", not just that some unspecified tool was invoked.
	tool := meta.JSONRPCMethod
	if meta.MCPTool != "" {
		tool = meta.MCPTool
	}

	rec := Record{
		Event:           event,
		ClaimedAgentID:  meta.AgentID,
		VerifiedAgentID: meta.VerifiedAgentID,
		TaskID:          meta.VerifiedTaskID,
		SPIFFEID:        meta.SPIFFEID,
		JTI:             meta.VerifiedJTI,
		UpstreamName:    upstream,
		Tool:            tool,
		HTTPMethod:      meta.Method,
		Path:            meta.Path,
	}

	if len(meta.RequestBody) > 0 {
		sum := sha256.Sum256(meta.RequestBody)
		rec.PromptSHA256 = hex.EncodeToString(sum[:])
		rec.PromptBytesTotal = len(meta.RequestBody)

		excerpt := meta.RequestBody
		truncated := false
		if len(excerpt) > s.maxExcerptBytes {
			excerpt = excerpt[:s.maxExcerptBytes]
			truncated = true
		}
		if utf8.Valid(excerpt) {
			rec.PromptExcerpt = string(excerpt)
		} else {
			// Binary/non-text content: we don't write it as unreadable text
			// — the SHA-256 digest above remains the proof of integrity.
			rec.PromptExcerpt = "[binary content — see prompt_sha256]"
		}
		rec.PromptTruncated = truncated
	}

	return rec
}

func (s *Sink) append(rec Record) error {
	if _, err := s.chain.Append(rec); err != nil {
		// Default is fail-open: the error is logged with high severity but
		// the request proceeds. With SetFailClosed(true) the *request*
		// record (written before forwarding) vetoes the call; response and
		// rejection records are written after the fact, so a failure there
		// can only be logged.
		slog.Error("nexus.compliance.chain_write_failed",
			"event", "chain_write_failed",
			"chain_event", rec.Event,
			"error", err.Error(),
		)
		return err
	}
	return nil
}

func decisionForStatus(statusCode int) string {
	if statusCode >= 200 && statusCode < 400 {
		return "allowed"
	}
	return "rejected"
}
