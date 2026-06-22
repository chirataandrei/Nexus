// Package logging provides structured logging for requests flowing
// through the gateway: JSON on stdout by default, but the AuditSink
// interface lets any other implementation (e.g. a tamper-evident WORM
// ledger) plug in without changing the rest of the gateway.
package logging

import (
	"log/slog"

	"nexus-gateway/internal/parser"
)

// AuditSink is the interface any request-logging destination must
// implement. NewStdoutLogger is the default implementation;
// compliance.Sink adds writing to a tamper-evident ledger, without
// changing the rest of the gateway.
type AuditSink interface {
	RecordRequest(meta *parser.RequestMeta, upstream string)
	RecordResponse(meta *parser.RequestMeta, upstream string, statusCode int, durationMS int64)
	RecordRejection(meta *parser.RequestMeta, reason string)
}

// StdoutLogger is a minimal AuditSink implementation that writes
// structured JSON events to stdout using the standard library's
// log/slog.
type StdoutLogger struct {
	logger *slog.Logger
}

// NewStdoutLogger builds an AuditSink that writes JSON to stdout, using
// the process's default slog logger (slog.Default()). main.go
// configures that handler once, so all gateway events — including the
// ones emitted directly from internal/identity — share the same
// consistent JSON format on stdout.
func NewStdoutLogger() *StdoutLogger {
	return &StdoutLogger{logger: slog.Default()}
}

func (l *StdoutLogger) RecordRequest(meta *parser.RequestMeta, upstream string) {
	l.logger.Info("nexus.request",
		"event", "request_received",
		"upstream", upstream,
		"protocol", string(meta.Protocol),
		"http_method", meta.Method,
		"path", meta.Path,
		"jsonrpc_method", meta.JSONRPCMethod,
		"mcp_tool", meta.MCPTool,
		"agent_id", meta.AgentID,
		"remote_addr", meta.RemoteAddr,
		"content_length", meta.ContentLength,
		"required_scope", meta.RequiredScope,
		"spiffe_id", meta.SPIFFEID,
		"verified_agent_id", meta.VerifiedAgentID,
		"verified_task_id", meta.VerifiedTaskID,
		"verified_scopes", meta.VerifiedScopes,
	)
}

func (l *StdoutLogger) RecordResponse(meta *parser.RequestMeta, upstream string, statusCode int, durationMS int64) {
	l.logger.Info("nexus.response",
		"event", "response_returned",
		"upstream", upstream,
		"path", meta.Path,
		"agent_id", meta.AgentID,
		"verified_agent_id", meta.VerifiedAgentID,
		"status_code", statusCode,
		"duration_ms", durationMS,
	)
}

func (l *StdoutLogger) RecordRejection(meta *parser.RequestMeta, reason string) {
	l.logger.Warn("nexus.rejected",
		"event", "request_rejected",
		"path", meta.Path,
		"agent_id", meta.AgentID,
		"required_scope", meta.RequiredScope,
		"reason", reason,
	)
}

// multiSink sends every event to multiple AuditSinks, in order — used
// to keep the human-readable operational logs on stdout (StdoutLogger)
// running in parallel with writes to the tamper-evident compliance
// ledger (compliance.Sink); the two aren't mutually exclusive.
type multiSink struct {
	sinks []AuditSink
}

// Fanout combines multiple AuditSinks into one. Nil sinks are ignored.
func Fanout(sinks ...AuditSink) AuditSink {
	nonNil := make([]AuditSink, 0, len(sinks))
	for _, s := range sinks {
		if s != nil {
			nonNil = append(nonNil, s)
		}
	}
	return &multiSink{sinks: nonNil}
}

func (m *multiSink) RecordRequest(meta *parser.RequestMeta, upstream string) {
	for _, s := range m.sinks {
		s.RecordRequest(meta, upstream)
	}
}

func (m *multiSink) RecordResponse(meta *parser.RequestMeta, upstream string, statusCode int, durationMS int64) {
	for _, s := range m.sinks {
		s.RecordResponse(meta, upstream, statusCode, durationMS)
	}
}

func (m *multiSink) RecordRejection(meta *parser.RequestMeta, reason string) {
	for _, s := range m.sinks {
		s.RecordRejection(meta, reason)
	}
}
