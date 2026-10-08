package finops_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"nexus-gateway/internal/config"
	"nexus-gateway/internal/finops"
	"nexus-gateway/internal/parser"
	"nexus-gateway/internal/proxy"
)

// fixedAgentValidator stands in for the SPIFFE validator: it marks every
// request as coming from the same verified agent and task.
type fixedAgentValidator struct{ agent, task string }

func (v fixedAgentValidator) Validate(_ context.Context, meta *parser.RequestMeta, _ *http.Request) error {
	meta.VerifiedAgentID = v.agent
	meta.VerifiedTaskID = v.task
	return nil
}

// TestBudget_ConcurrentRequestsStopExactlyAtLimit fires hundreds of
// simultaneous requests for one agent. Each costs exactly $0.10 and the
// daily budget is $1.00, so exactly 10 may reach the upstream; every
// other request must get 429.
func TestBudget_ConcurrentRequestsStopExactlyAtLimit(t *testing.T) {
	const (
		requests    = 500
		wantAllowed = 10
	)

	var upstreamHits atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"usage":{"prompt_tokens":600,"completion_tokens":400,"total_tokens":1000}}`))
	}))
	defer upstream.Close()

	policyFile := filepath.Join(t.TempDir(), "policies.json")
	if err := os.WriteFile(policyFile, []byte(`{"default_daily_budget_usd": 1.0, "default_max_cost_per_request_usd": 0.10}`), 0o600); err != nil {
		t.Fatal(err)
	}
	policies, err := finops.LoadPolicyRegistry(policyFile)
	if err != nil {
		t.Fatal(err)
	}
	ledger := finops.NewLedger()
	cfg := &config.Config{
		ListenAddr: ":0",
		Upstreams: []config.Upstream{{
			Name: "llm", PathPrefix: "/v1/llm", TargetURL: upstream.URL,
			PricePerThousandTokensUSD: 0.10, // 1000 tokens => $0.10
		}},
	}
	srv, err := proxy.NewServer(cfg,
		fixedAgentValidator{agent: "agent-1", task: "task-1"},
		finops.NewEnforcer(policies, ledger),
		finops.NewRecorder(ledger),
		nil)
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	gw := httptest.NewServer(srv.Handler())
	defer gw.Close()

	var ok, limited, other atomic.Int32
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			resp, err := http.Post(gw.URL+"/v1/llm/chat", "application/json", strings.NewReader(`{}`))
			if err != nil {
				other.Add(1)
				return
			}
			defer resp.Body.Close()
			switch resp.StatusCode {
			case http.StatusOK:
				ok.Add(1)
			case http.StatusTooManyRequests:
				limited.Add(1)
			default:
				other.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if other.Load() != 0 {
		t.Fatalf("%d requests failed with an unexpected status/error", other.Load())
	}
	if got := ok.Load(); got != wantAllowed {
		t.Errorf("allowed = %d, want exactly %d (budget overshoot: %d extra upstream calls)",
			got, wantAllowed, int(upstreamHits.Load())-wantAllowed)
	}
	if got := upstreamHits.Load(); got != wantAllowed {
		t.Errorf("upstream hits = %d, want %d", got, wantAllowed)
	}
	if ok.Load()+limited.Load() != requests {
		t.Errorf("ok(%d)+429(%d) != %d", ok.Load(), limited.Load(), requests)
	}
}
