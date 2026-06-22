// Comanda nexus-gateway pornește gateway-ul Layer 7 al Nexus Trust
// Protocol: serverul care intermediază traficul dintre agenții IA și
// modelele LLM / serviciile interne.
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
	configPath := flag.String("config", "configs/config.json", "calea către fișierul de configurare JSON")
	flag.Parse()

	// Toate evenimentele (gateway + identitate) folosesc același logger
	// JSON pe stdout, pentru un flux de audit consistent.
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo})))

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("nexus-gateway: configurare invalidă: %v", err)
	}

	// Lanțul de conformitate WORM. OpenChain verifică integritatea lanțului
	// existent ÎNAINTE de a permite scrieri noi — dacă a fost modificat
	// retroactiv în afara gateway-ului, pornirea este refuzată (fail-closed),
	// în loc să continue tăcut peste o încălcare deja produsă.
	chain, err := compliance.OpenChain(cfg.ComplianceLedgerFile, cfg.ComplianceRetentionMonths)
	if err != nil {
		log.Fatalf("nexus-gateway: lanțul de conformitate este indisponibil sau corupt: %v", err)
	}
	defer chain.Close()

	// Kill-switch (Articolul 14): registrul de suspendări, consultat de
	// validatorul de identitate la fiecare cerere și la fiecare emitere
	// de token nou — o suspendare are efect instantaneu și global.
	suspensionRegistry := compliance.NewSuspensionRegistry()

	// Registrul de agenți + autoritatea de identitate (AIMS).
	agentsRegistry, err := identity.LoadRegistry(cfg.AgentsFile, cfg.MaxTokenTTL())
	if err != nil {
		log.Fatalf("nexus-gateway: nu pot încărca registrul de agenți: %v", err)
	}
	issuer, err := identity.NewIssuer(cfg.TrustDomain, cfg.DefaultTokenTTL())
	if err != nil {
		log.Fatalf("nexus-gateway: nu pot iniția autoritatea de identitate: %v", err)
	}
	validator := identity.NewSPIFFEValidator(issuer.PublicKey(), cfg.TrustDomain, suspensionRegistry)

	// Politici de buget per agent + ledger de consum în memorie.
	finopsPolicies, err := finops.LoadPolicyRegistry(cfg.FinOpsPoliciesFile)
	if err != nil {
		log.Fatalf("nexus-gateway: nu pot încărca politicile FinOps: %v", err)
	}
	ledger := finops.NewLedger()
	budgetEnforcer := finops.NewEnforcer(finopsPolicies, ledger)
	spendRecorder := finops.NewRecorder(ledger)

	// costLookup leagă (fără import direct) ledger-ul FinOps de sink-ul de
	// conformitate, ca fiecare înregistrare de răspuns din lanțul WORM să
	// includă și cheltuiala cumulată de azi a agentului respectiv.
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

	// audit scrie în paralel pe stdout (operațional, lizibil de om) și în
	// lanțul WORM de conformitate — cele două nu se exclud.
	audit := logging.Fanout(logging.NewStdoutLogger(), complianceSink)

	srv, err := proxy.NewServer(cfg, validator, budgetEnforcer, spendRecorder, audit)
	if err != nil {
		log.Fatalf("nexus-gateway: nu pot construi gateway-ul: %v", err)
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
		log.Printf("nexus-gateway: ascult pe %s (config: %s, trust_domain: %s)", cfg.ListenAddr, *configPath, cfg.TrustDomain)
		log.Printf("nexus-gateway: identitate activă — orice cerere către upstream-uri necesită JWT-SVID valid (vezi POST /nexus/identity/token)")
		log.Printf("nexus-gateway: dashboard FinOps disponibil la GET /nexus/finops/dashboard")
		log.Printf("nexus-gateway: registru de conformitate la %s (retenție: %d luni) — kill-switch la POST /nexus/control/suspend", cfg.ComplianceLedgerFile, cfg.ComplianceRetentionMonths)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("nexus-gateway: server oprit cu eroare: %v", err)
		}
	}()

	waitForShutdown(httpServer, cfg.ShutdownTimeout())
}

// waitForShutdown blochează până la SIGINT/SIGTERM, apoi închide serverul
// HTTP controlat, lăsând cererile în curs să se termine în limita
// timeout-ului configurat.
func waitForShutdown(srv *http.Server, timeout time.Duration) {
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, syscall.SIGINT, syscall.SIGTERM)
	<-stop

	log.Println("nexus-gateway: semnal de închidere primit, opresc gateway-ul...")
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		log.Printf("nexus-gateway: închidere forțată după timeout: %v", err)
	} else {
		log.Println("nexus-gateway: închidere reușită.")
	}
}
