package identity

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
)

// newJTI generează un identificator unic (JWT ID) pentru fiecare token
// emis, util pentru trasabilitate în jurnalul de conformitate (fiecare
// JTI poate fi corelat cu exact un token emis, o singură dată).
func newJTI() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("identity: nu pot genera jti: %w", err)
	}
	return hex.EncodeToString(buf), nil
}
