// Punctele de extensie pe care gateway-ul le expune: identitate, buget și
// contorizarea cheltuielilor se conectează aici prin interfețe, nu prin
// modificări ad-hoc ale buclei principale a proxy-ului.
package proxy

import (
	"context"
	"net/http"

	"nexus-gateway/internal/parser"
)

// Validator decide dacă o cerere are dreptul să ajungă la upstream.
// NoopValidator acceptă tot; identity.SPIFFEValidator o înlocuiește cu
// validarea identității criptografice (JWT-SVID).
type Validator interface {
	Validate(ctx context.Context, meta *parser.RequestMeta, r *http.Request) error
}

// BudgetEnforcer decide dacă o cerere se încadrează în politica de cost
// alocată agentului/sarcinii, ÎNAINTE ca cererea să ajungă la upstream.
// NoopBudgetEnforcer nu impune nicio limită; finops.Enforcer adaugă
// "circuit breaking" real pe baza consumului de tokeni/cost per agent și
// per sarcină.
type BudgetEnforcer interface {
	Authorize(ctx context.Context, meta *parser.RequestMeta) error
}

// SpendRecorder este apelat după ce s-a primit răspunsul de la upstream,
// cu corpul răspunsului (de regulă JSON-ul unui model LLM, care conține
// un câmp "usage" cu tokenii consumați). NoopSpendRecorder nu face nimic;
// finops.Recorder extrage tokenii reali și actualizează ledger-ul de cost,
// astfel încât *următoarea* cerere a agentului să fie evaluată corect de
// BudgetEnforcer.
//
// pricePerThousandTokensUSD este prețul configurat pentru upstream-ul
// apelat (config.Upstream.PricePerThousandTokensUSD), transmis aici ca
// să nu fie nevoie ca implementarea SpendRecorder să cunoască detalii de
// configurare a gateway-ului.
type SpendRecorder interface {
	RecordSpend(ctx context.Context, meta *parser.RequestMeta, upstreamName string, pricePerThousandTokensUSD float64, responseBody []byte)
}

// NoopValidator nu respinge nimic — implicit cât nu e conectat un
// validator real.
type NoopValidator struct{}

func (NoopValidator) Validate(_ context.Context, _ *parser.RequestMeta, _ *http.Request) error {
	return nil
}

// NoopBudgetEnforcer nu impune nicio limită de buget.
type NoopBudgetEnforcer struct{}

func (NoopBudgetEnforcer) Authorize(_ context.Context, _ *parser.RequestMeta) error {
	return nil
}

// NoopSpendRecorder nu înregistrează niciun cost.
type NoopSpendRecorder struct{}

func (NoopSpendRecorder) RecordSpend(_ context.Context, _ *parser.RequestMeta, _ string, _ float64, _ []byte) {
}
