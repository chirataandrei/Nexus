package identity

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// newJTI generates a unique identifier (JWT ID) for each issued token,
// useful for traceability in the compliance ledger (each JTI can be
// correlated with exactly one issued token, exactly once).
func newJTI() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("identity: cannot generate jti: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
