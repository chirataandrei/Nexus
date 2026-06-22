// recorder.go implements proxy.SpendRecorder: it reads the real token
// consumption from an LLM response already received from the upstream
// and records it in the Ledger, multiplied by that upstream's
// configured price per 1000 tokens. This is what makes the agent's
// *next* request get evaluated correctly by Enforcer.
package finops

import (
	"context"
	"log/slog"

	"nexus-gateway/internal/parser"
)

// Recorder implements proxy.SpendRecorder on top of a Ledger.
type Recorder struct {
	ledger *Ledger
}

// NewRecorder builds a Recorder.
func NewRecorder(ledger *Ledger) *Recorder {
	return &Recorder{ledger: ledger}
}

// RecordSpend implements proxy.SpendRecorder. responseBody is the JSON
// body of the response received from the upstream (the proxy restores
// it intact for the client — see internal/proxy — the recorder only
// inspects it). pricePerThousandTokensUSD comes from the upstream's
// configuration (config.Upstream.PricePerThousandTokensUSD); 0 means
// "don't calculate cost" for that upstream (e.g. an internal tool that
// isn't a per-token-billed LLM model).
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
