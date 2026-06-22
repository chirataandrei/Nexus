package config

import "testing"

func validBaseConfig() Config {
	return Config{
		ListenAddr:                ":8080",
		TrustDomain:               "nexus.trust",
		AgentsFile:                "agents.json",
		FinOpsPoliciesFile:        "finops_policies.json",
		ComplianceLedgerFile:      "ledger.jsonl",
		ComplianceRetentionMonths: 6,
		Upstreams: []Upstream{
			{Name: "mock", PathPrefix: "/v1/mock", TargetURL: "http://localhost:9000"},
		},
	}
}

func TestValidate_AcceptsCompleteConfig(t *testing.T) {
	if err := validBaseConfig().Validate(); err != nil {
		t.Errorf("a complete config should be valid: %v", err)
	}
}

func TestValidate_RejectsRetentionBelowSixMonths(t *testing.T) {
	cfg := validBaseConfig()
	cfg.ComplianceRetentionMonths = 3
	if err := cfg.Validate(); err == nil {
		t.Error("Validate should reject a retention period below 6 months (Article 12)")
	}
}

func TestValidate_RejectsMissingComplianceLedgerFile(t *testing.T) {
	cfg := validBaseConfig()
	cfg.ComplianceLedgerFile = ""
	if err := cfg.Validate(); err == nil {
		t.Error("Validate should reject a missing compliance_ledger_file")
	}
}

func TestValidate_RejectsMissingTrustDomain(t *testing.T) {
	cfg := validBaseConfig()
	cfg.TrustDomain = ""
	if err := cfg.Validate(); err == nil {
		t.Error("Validate should reject a missing trust_domain")
	}
}

func TestValidate_RejectsDuplicatePathPrefix(t *testing.T) {
	cfg := validBaseConfig()
	cfg.Upstreams = append(cfg.Upstreams, Upstream{Name: "dup", PathPrefix: "/v1/mock", TargetURL: "http://x"})
	if err := cfg.Validate(); err == nil {
		t.Error("Validate should reject duplicate path prefixes")
	}
}

func TestDefaultTokenTTL_FallsBackToFiveMinutes(t *testing.T) {
	cfg := Config{}
	if got := cfg.DefaultTokenTTL(); got.Minutes() != 5 {
		t.Errorf("DefaultTokenTTL = %v, want 5 minutes", got)
	}
}
