// suspension.go declares the extension point through which
// internal/compliance.SuspensionRegistry can instantly revoke an
// agent's right to be validated or to receive new tokens — the kill
// switch required by Article 14 (human oversight). The identity package
// doesn't import compliance; any implementation satisfying this
// interface (duck typing) can be wired in from main.go.
package identity

// SuspensionChecker decides whether an agent is suspended by an
// operator. The second return value is the suspension reason, useful
// in error messages and logging.
type SuspensionChecker interface {
	IsSuspended(agentID string) (bool, string)
}

// NoopSuspensionChecker is the default implementation: no agent is ever
// suspended. Used when no real implementation is wired in.
type NoopSuspensionChecker struct{}

func (NoopSuspensionChecker) IsSuspended(_ string) (bool, string) { return false, "" }
