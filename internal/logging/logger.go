// Package logging oferă jurnalizarea structurată a cererilor care trec
// prin gateway: implicit ca JSON pe stdout, dar interfața AuditSink
// permite oricărei alte implementări (ex. un registru imutabil
// tamper-evident / WORM) să se conecteze fără să schimbe restul
// gateway-ului.
package logging

import (
	"log/slog"

	"nexus-gateway/internal/parser"
)

// AuditSink este interfața pe care orice destinație de jurnalizare a
// cererilor trebuie să o implementeze. NewStdoutLogger este implementarea
// implicită; compliance.Sink adaugă scrierea într-un ledger
// tamper-evident, fără a schimba restul gateway-ului.
type AuditSink interface {
	RecordRequest(meta *parser.RequestMeta, upstream string)
	RecordResponse(meta *parser.RequestMeta, upstream string, statusCode int, durationMS int64)
	RecordRejection(meta *parser.RequestMeta, reason string)
}

// StdoutLogger este o implementare minimă a AuditSink, care scrie evenimente
// structurate JSON pe stdout folosind log/slog din biblioteca standard.
type StdoutLogger struct {
	logger *slog.Logger
}

// NewStdoutLogger construiește un AuditSink care scrie JSON pe stdout,
// folosind logger-ul slog implicit al procesului (slog.Default()). main.go
// configurează acel handler o singură dată, astfel încât toate evenimentele
// gateway-ului — inclusiv cele emise direct din internal/identity — au
// același format JSON consistent pe stdout.
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

// multiSink trimite fiecare eveniment către mai multe AuditSink-uri, în
// ordine — ca să păstrăm logurile operaționale lizibile de pe stdout
// (StdoutLogger) în paralel cu scrierea în lanțul de conformitate
// tamper-evident (compliance.Sink); cele două nu se exclud.
type multiSink struct {
	sinks []AuditSink
}

// Fanout combină mai multe AuditSink-uri într-unul singur. Sink-urile nil
// sunt ignorate.
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
