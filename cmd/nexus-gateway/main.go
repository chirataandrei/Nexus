// The nexus-gateway command starts Nexus Trust Protocol's Layer 7
// gateway: the server that intermediates traffic between AI agents and
// LLM models / internal services.
package main

import (
	"context"
	"errors"
	"flag"
	"log"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"nexus-gateway/internal/compliance"
	"nexus-gateway/internal/config"
	"nexus-gateway/internal/finops"
	"nexus-gateway/internal/identity"
	"nexus-gateway/internal/logging"
	"nexus-gateway/internal/proxy"
)

func main() {
	configPath := flag.String("config", "configs/config.json", "path to the JSON configuration file")
	flag.Parse()

	// All events (gateway + identity) use the same JSON logger on
	// stdout, for a consistent audit stream.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("nexus-gateway: invalid configuration: %v", err)
	}

	// The WORM compliance chain. OpenChain verifies the existing chain's
	// integrity BEFORE allowing new writes — if it was retroactively
	// modified outside the gateway, startup is refused (fail-closed),
	// instead of silently continuing past a violation that already
	// happened.
	chain, err := compliance.OpenChain(cfg.ComplianceLedgerFile, cfg.ComplianceRetentionMonths)
	if err != nil {
		log.Fatalf("nexus-gateway: the compliance chain is unavailable or corrupted: %v", err)
	}
	defer chain.Close()

	// Kill switch (Article 14): the suspension registry, consulted by the
	// identity validator on every request and on every new token issuance
	// — a suspension takes effect instantly and globally.
	suspensionRegistry := compliance.NewSuspensionRegistry()

	// Agent registry + identity authority (AIMS).
	agentsRegistry, err := identity.LoadRegistry(cfg.AgentsFile, cfg.MaxTokenTTL())
	if err != nil {
		log.Fatalf("nexus-gateway: cannot load agent registry: %v", err)
	}
	issuer, err := identity.NewIssuer(cfg.TrustDomain, cfg.DefaultTokenTTL())
	if err != nil {
		log.Fatalf("nexus-gateway: cannot initialize identity authority: %v", err)
	}
	validator := identity.NewSPIFFEValidator(issuer.PublicKey(), cfg.TrustDomain, suspensionRegistry)

	// Per-agent budget policies + in-memory consumption ledger.
	finopsPolicies, err := finops.LoadPolicyRegistry(cfg.FinOpsPoliciesFile)
	if err != nil {
		log.Fatalf("nexus-gateway: cannot load FinOps policies: %v", err)
	}
	ledger := finops.NewLedger()
	budgetEnforcer := finops.NewEnforcer(finopsPolicies, ledger)
	spendRecorder := finops.NewRecorder(ledger)

	// costLookup ties the FinOps ledger to the compliance sink (without a
	// direct import), so every response record in the WORM chain also
	// includes that agent's cumulative spend for today.
	costLookup := func(agentID, taskID string) (float64, bool) {
		if agentID == "" {
			return 0, false
		}
		for _, s := range ledger.Snapshot() {
			if s.AgentID == agentID {
				return s.SpentUSD, true
			}
		}
		return 0, false
	}
	complianceSink := compliance.NewSink(chain, costLookup, cfg.MaxPromptExcerptBytes)

	// audit writes in parallel to stdout (operational, human-readable)
	// and to the WORM compliance chain — the two aren't mutually
	// exclusive.
	audit := logging.Fanout(logging.NewStdoutLogger(), complianceSink)

	srv, err := proxy.NewServer(cfg, validator, budgetEnforcer, spendRecorder, audit)
	if err != nil {
		log.Fatalf("nexus-gateway: cannot build the gateway: %v", err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/nexus/identity/token", identity.TokenHandler(agentsRegistry, issuer, suspensionRegistry))
	mux.HandleFunc("/nexus/finops/usage", finops.UsageHandler(ledger, finopsPolicies))
	mux.HandleFunc("/nexus/finops/policies", finops.PoliciesHandler(finopsPolicies))
	mux.HandleFunc("/nexus/finops/dashboard", finops.DashboardHandler())
	mux.HandleFunc("/nexus/control/suspend", compliance.SuspendHandler(suspensionRegistry, chain))
	mux.HandleFunc("/nexus/control/resume", compliance.ResumeHandler(suspensionRegistry, chain))
	mux.HandleFunc("/nexus/control/suspended", compliance.SuspendedListHandler(suspensionRegistry))
	mux.HandleFunc("/nexus/compliance/verify", compliance.VerifyHandler(cfg.ComplianceLedgerFile))
	mux.Handle("/", srv.Handler())

	httpServer := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           mux,
		ReadHeaderTimeout: cfg.ReadHeaderTimeout(),
	}

	go func() {
		log.Printf("nexus-gateway: listening on %s (config: %s, trust_domain: %s)", cfg.ListenAddr, *configPath, cfg.TrustDomain)
		log.Printf("nexus-gateway: identity enforcement active — every request to an upstream requires a valid JWT-SVID (see POST /nexus/identity/token)")
		log.Printf("nexus-gateway: FinOps dashboard available at GET /nexus/finops/dashboard")
		log.Printf("nexus-gateway: compliance ledger at %s (retention: %d months) — kill switch at POST /nexus/control/suspend", cfg.ComplianceLedgerFile, cfg.ComplianceRetentionMonths)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("nexus-gateway: server stopped with an error: %v", err)
		}
	}()

	waitForShutdown(httpServer, cfg.ShutdownTimeout())
}

// waitForShutdown blocks until SIGINT/SIGTERM, then shuts down the HTTP
// server in a controlled way, letting in-flight requests finish within
// the configured timeout.
func waitForShutdown(srv *http.Server, timeout time.Duration) {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	log.Println("nexus-gateway: shutdown signal received, stopping the gateway...")
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("nexus-gateway: forced shutdown after timeout: %v", err)
	} else {
		log.Println("nexus-gateway: shutdown successful.")
	}
}
