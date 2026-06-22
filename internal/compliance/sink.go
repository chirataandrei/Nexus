// sink.go conectează lanțul de conformitate la fluxul de cereri al
// gateway-ului: implementează logging.AuditSink (aceeași interfață
// folosită de StdoutLogger) astfel încât fiecare cerere procesată de
// proxy este, în paralel, scrisă și în registrul tamper-evident — fără
// nicio modificare a buclei principale din internal/proxy.
package compliance

import (
	"crypto/sha256"
	"encoding/hex"
	"log/slog"
	"unicode/utf8"

	"nexus-gateway/internal/parser"
)

// CostLookup este o funcție care returnează cheltuiala cumulată de azi a
// unui agent/sarcină, dacă este cunoscută. Sink-ul de conformitate nu
// importă pachetul finops — apelantul (main.go) îi oferă o funcție
// construită pe baza ledger-ului FinOps, păstrând pachetele independente.
type CostLookup func(agentID, taskID string) (spentUSDToday float64, ok bool)

// Sink este implementarea logging.AuditSink care scrie în Chain.
type Sink struct {
	chain           *Chain
	costLookup      CostLookup
	maxExcerptBytes int
}

// NewSink construiește un Sink. maxExcerptBytes controlează cât din
// corpul cererii este copiat ca text lizibil în lanț (digest-ul SHA-256
// este mereu integral, indiferent de această limită). costLookup poate
// fi nil, caz în care câmpul de cost cumulat este pur și simplu omis.
func NewSink(chain *Chain, costLookup CostLookup, maxExcerptBytes int) *Sink {
	if maxExcerptBytes <= 0 {
		maxExcerptBytes = 4096
	}
	return &Sink{chain: chain, costLookup: costLookup, maxExcerptBytes: maxExcerptBytes}
}

// RecordRequest implementează logging.AuditSink.
func (s *Sink) RecordRequest(meta *parser.RequestMeta, upstream string) {
	rec := s.baseRecord("request_received", meta, upstream)
	s.append(rec)
}

// RecordResponse implementează logging.AuditSink.
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
	s.append(rec)
}

// RecordRejection implementează logging.AuditSink.
func (s *Sink) RecordRejection(meta *parser.RequestMeta, reason string) {
	rec := s.baseRecord("request_rejected", meta, meta.UpstreamName)
	rec.Decision = "rejected"
	rec.Reason = reason
	s.append(rec)
}

// baseRecord construiește câmpurile comune tuturor evenimentelor pe
// baza metadatelor cererii — inclusiv digest-ul/excerpt-ul promptului.
func (s *Sink) baseRecord(event string, meta *parser.RequestMeta, upstream string) Record {
	// Tool preferă numele exact al instrumentului MCP, mai precis decât
	// metoda JSON-RPC generică "tools/call" — un auditor vede direct
	// "send_email", nu doar că s-a invocat un instrument nespecificat.
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
			// Conținut binar/non-text: nu îl scriem ca text ilizibil —
			// digest-ul SHA-256 de mai sus rămâne dovada de integritate.
			rec.PromptExcerpt = "[conținut binar — vezi prompt_sha256]"
		}
		rec.PromptTruncated = truncated
	}

	return rec
}

func (s *Sink) append(rec Record) {
	if _, err := s.chain.Append(rec); err != nil {
		// Decizie documentată: o eroare de scriere în lanțul de
		// conformitate este logată cu severitate, dar NU blochează
		// răspunsul către agent (fail-open). Un mediu de producție cu
		// cerințe stricte de conformitate ar trebui să configureze
		// fail-closed (respingerea cererilor cât timp lanțul e
		// indisponibil) — marcat explicit ca lucru viitor în README.
		slog.Error("nexus.compliance.chain_write_failed",
			"event", "chain_write_failed",
			"chain_event", rec.Event,
			"error", err.Error(),
		)
	}
}

func decisionForStatus(statusCode int) string {
	if statusCode >= 200 && statusCode < 400 {
		return "allowed"
	}
	return "rejected"
}
