// The extension points the gateway exposes: identity, budget, and spend
// tracking plug in here through interfaces, not through ad-hoc changes
// to the proxy's main loop.
package proxy

import (
	"context"
	"net/http"

	"nexus-gateway/internal/parser"
)

// Validator decides whether a request is allowed to reach the upstream.
// NoopValidator accepts everything; identity.SPIFFEValidator replaces it
// with cryptographic identity validation (JWT-SVID).
type Validator interface {
	Validate(ctx context.Context, meta *parser.RequestMeta, r *http.Request) error
}

// BudgetEnforcer decides whether a request fits the cost policy
// allocated to the agent/task, BEFORE the request reaches the upstream.
// NoopBudgetEnforcer imposes no limit; finops.Enforcer adds real
// "circuit breaking" based on token/cost consumption per agent and per
// task.
type BudgetEnforcer interface {
	Authorize(ctx context.Context, meta *parser.RequestMeta) error
}

// SpendRecorder is called after the response has been received from the
// upstream, with the response body (typically an LLM's JSON, which
// contains a "usage" field with the tokens consumed). NoopSpendRecorder
// does nothing; finops.Recorder extracts the real token counts and
// updates the cost ledger, so the agent's *next* request is evaluated
// correctly by BudgetEnforcer.
//
// pricePerThousandTokensUSD is the price configured for the upstream
// being called (config.Upstream.PricePerThousandTokensUSD), passed in
// here so the SpendRecorder implementation doesn't need to know
// anything about the gateway's configuration.
type SpendRecorder interface {
	RecordSpend(ctx context.Context, meta *parser.RequestMeta, upstreamName string, pricePerThousandTokensUSD float64, responseBody []byte)
}

// NoopValidator rejects nothing — the default while no real validator
// is wired in.
type NoopValidator struct{}

func (NoopValidator) Validate(_ context.Context, _ *parser.RequestMeta, _ *http.Request) error {
	return nil
}

// NoopBudgetEnforcer imposes no budget limit.
type NoopBudgetEnforcer struct{}

func (NoopBudgetEnforcer) Authorize(_ context.Context, _ *parser.RequestMeta) error {
	return nil
}

// NoopSpendRecorder records no cost.
type NoopSpendRecorder struct{}

func (NoopSpendRecorder) RecordSpend(_ context.Context, _ *parser.RequestMeta, _ string, _ float64, _ []byte) {
}
