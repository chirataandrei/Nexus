// recorder.go implementează proxy.SpendRecorder: citește consumul real
// de tokeni dintr-un răspuns LLM deja primit de la upstream și îl
// înregistrează în Ledger, înmulțit cu prețul per 1000 de tokeni
// configurat pentru acel upstream. Această înregistrare este ce face ca
// *următoarea* cerere a agentului să fie evaluată corect de Enforcer.
package finops

import (
	"context"
	"log/slog"

	"nexus-gateway/internal/parser"
)

// Recorder implementează proxy.SpendRecorder pe baza unui Ledger.
type Recorder struct {
	ledger *Ledger
}

// NewRecorder construiește un Recorder.
func NewRecorder(ledger *Ledger) *Recorder {
	return &Recorder{ledger: ledger}
}

// RecordSpend implementează proxy.SpendRecorder. responseBody este corpul
// JSON al răspunsului primit de la upstream (proxy-ul îl restaurează
// intact pentru client — vezi internal/proxy — recorder-ul doar îl
// inspectează). pricePerThousandTokensUSD vine din configurația
// upstream-ului (config.Upstream.PricePerThousandTokensUSD); 0 înseamnă
// "nu se calculează cost" pentru acel upstream (ex. un instrument intern
// care nu este un model LLM taxat per token).
func (r *Recorder) RecordSpend(_ context.Context, meta *parser.RequestMeta, upstreamName string, pricePerThousandTokensUSD float64, responseBody []byte) {
	agentID := meta.VerifiedAgentID
	if agentID == "" {
		return
	}

	tokens, ok := ExtractTokens(responseBody)
	if !ok || tokens <= 0 {
		return
	}

	costUSD := 0.0
	if pricePerThousandTokensUSD > 0 {
		costUSD = float64(tokens) / 1000.0 * pricePerThousandTokensUSD
	}

	r.ledger.RecordSpend(agentID, meta.VerifiedTaskID, tokens, costUSD)

	slog.Info("nexus.finops.spend_recorded",
		"event", "spend_recorded",
		"agent_id", agentID,
		"task_id", meta.VerifiedTaskID,
		"upstream", upstreamName,
		"tokens", tokens,
		"cost_usd", costUSD,
	)
}
