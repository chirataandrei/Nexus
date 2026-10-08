// Command nexus-bench measures the latency and throughput the gateway
// adds on top of calling an upstream directly. It starts a fake local
// upstream and the gateway in-process, then drives both with the same
// closed-loop load (N workers, each sending requests back to back) and
// prints requests/second, p50, p95 and p99 for each path.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"nexus-gateway/internal/config"
	"nexus-gateway/internal/finops"
	"nexus-gateway/internal/parser"
	"nexus-gateway/internal/proxy"
)

const llmResponse = `{"id":"x","usage":{"prompt_tokens":10,"completion_tokens":5,"total_tokens":15}}`

type fixedAgent struct{}

func (fixedAgent) Validate(_ context.Context, m *parser.RequestMeta, _ *http.Request) error {
	m.VerifiedAgentID, m.VerifiedTaskID = "bench-agent", "bench-task"
	return nil
}

type result struct {
	name      string
	n         int
	elapsed   time.Duration
	latencies []time.Duration
}

func (r result) pct(p float64) time.Duration {
	if len(r.latencies) == 0 {
		return 0
	}
	return r.latencies[int(float64(len(r.latencies)-1)*p)]
}

func run(name, url string, workers int, dur time.Duration, body string) result {
	client := &http.Client{Transport: &http.Transport{
		MaxIdleConns: workers * 2, MaxIdleConnsPerHost: workers * 2,
	}}
	defer client.CloseIdleConnections()

	var mu sync.Mutex
	var all []time.Duration
	deadline := time.Now().Add(dur)
	start := time.Now()
	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			local := make([]time.Duration, 0, 4096)
			for time.Now().Before(deadline) {
				t0 := time.Now()
				resp, err := client.Post(url, "application/json", strings.NewReader(body))
				if err != nil {
					continue
				}
				_, _ = io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode == http.StatusOK {
					local = append(local, time.Since(t0))
				}
			}
			mu.Lock()
			all = append(all, local...)
			mu.Unlock()
		}()
	}
	wg.Wait()
	sort.Slice(all, func(i, j int) bool { return all[i] < all[j] })
	return result{name: name, n: len(all), elapsed: time.Since(start), latencies: all}
}

func main() {
	workers := flag.Int("c", 50, "concurrent workers")
	dur := flag.Duration("d", 10*time.Second, "duration per scenario")
	flag.Parse()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(llmResponse))
	}))
	defer upstream.Close()

	cfg := &config.Config{
		ListenAddr: ":0", MaxBodyBytes: 1 << 20,
		Upstreams: []config.Upstream{{Name: "llm", PathPrefix: "/v1/llm", TargetURL: upstream.URL, PricePerThousandTokensUSD: 0.001}},
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))

	dir, _ := os.MkdirTemp("", "nexus-bench")
	defer os.RemoveAll(dir)
	pf := filepath.Join(dir, "p.json")
	_ = os.WriteFile(pf, []byte(`{"default_daily_budget_usd":1000000,"default_max_cost_per_request_usd":0.0001}`), 0o600)
	policies, err := finops.LoadPolicyRegistry(pf)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	ledger := finops.NewLedger()

	plain, _ := proxy.NewServer(cfg, nil, nil, nil, discard{})
	full, _ := proxy.NewServer(cfg, fixedAgent{}, finops.NewEnforcer(policies, ledger), finops.NewRecorder(ledger), discard{})
	gwPlain := httptest.NewServer(plain.Handler())
	defer gwPlain.Close()
	gwFull := httptest.NewServer(full.Handler())
	defer gwFull.Close()

	body := `{"jsonrpc":"2.0","method":"tools/call","id":1,"params":{"name":"echo","arguments":{"text":"hello"}}}`
	// Warm-up so connection setup and runtime ramp-up don't skew results.
	run("warmup", upstream.URL+"/v1/llm", *workers, 2*time.Second, body)

	results := []result{
		run("direct (no gateway)", upstream.URL+"/v1/llm", *workers, *dur, body),
		run("gateway: proxy + parse", gwPlain.URL+"/v1/llm", *workers, *dur, body),
		run("gateway: + FinOps budget/spend", gwFull.URL+"/v1/llm", *workers, *dur, body),
	}
	fmt.Printf("workers=%d duration=%s body=%dB\n\n", *workers, *dur, len(body))
	fmt.Printf("%-34s %10s %10s %10s %10s %10s\n", "scenario", "req/s", "p50", "p95", "p99", "added p50")
	base := results[0].pct(0.5)
	for _, r := range results {
		fmt.Printf("%-34s %10.0f %10s %10s %10s %10s\n", r.name,
			float64(r.n)/r.elapsed.Seconds(), r.pct(0.5), r.pct(0.95), r.pct(0.99), r.pct(0.5)-base)
	}
}

// discard is an AuditSink that drops every record, so the benchmark
// measures the gateway's work rather than terminal I/O.
type discard struct{}

func (discard) RecordRequest(*parser.RequestMeta, string)              {}
func (discard) RecordRejection(*parser.RequestMeta, string)            {}
func (discard) RecordResponse(*parser.RequestMeta, string, int, int64) {}
