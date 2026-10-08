// restore.go rebuilds the security state that must survive a restart
// (the kill-switch list and revoked tokens) from the ledger itself.
//
// Every suspend, resume and revoke is already an append-only, hash-chained
// record, so the ledger is the durable source of truth: replaying it in
// order gives the same state the gateway had before it stopped. Because
// OpenChain verifies the chain first, an attacker cannot erase a
// suspension from the file without breaking startup.
package compliance

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// TokenRestorer is what RestoreState needs from the identity package's
// revocation list (an interface, so compliance doesn't import identity).
// RestoreRevoked must ignore a revocation old enough that the token has
// expired anyway.
type TokenRestorer interface {
	RestoreRevoked(jti string, revokedAt time.Time)
}

// RestoreSummary says what a replay found, for the startup log.
type RestoreSummary struct {
	Suspended int // agents suspended after replay
	Revoked   int // token_revoked records replayed
}

// RestoreState replays the ledger at path into the suspension registry
// and the revocation list. A missing ledger restores nothing. Call it
// after OpenChain succeeded, before serving traffic.
func RestoreState(path string, susp *SuspensionRegistry, rev TokenRestorer) (RestoreSummary, error) {
	var sum RestoreSummary
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return sum, nil
		}
		return sum, fmt.Errorf("compliance: cannot read ledger to restore state: %w", err)
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var rec Record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			return sum, fmt.Errorf("compliance: unreadable ledger record while restoring state: %w", err)
		}
		switch rec.Event {
		case "agent_suspended":
			if susp != nil && rec.VerifiedAgentID != "" {
				susp.restore(SuspensionRecord{
					AgentID:     rec.VerifiedAgentID,
					Reason:      rec.SuspensionReason,
					Operator:    rec.Operator,
					SuspendedAt: rec.Timestamp,
				})
			}
		case "agent_resumed":
			if susp != nil {
				susp.Resume(rec.VerifiedAgentID)
			}
		case "token_revoked":
			if rev != nil && rec.JTI != "" {
				rev.RestoreRevoked(rec.JTI, rec.Timestamp)
				sum.Revoked++
			}
		}
	}
	if err := sc.Err(); err != nil {
		return sum, fmt.Errorf("compliance: error reading ledger to restore state: %w", err)
	}
	if susp != nil {
		sum.Suspended = len(susp.List())
	}
	return sum, nil
}
