// suspension.go declară punctul de extensie prin care
// internal/compliance.SuspensionRegistry poate revoca instantaneu
// dreptul unui agent de a fi validat sau de a primi tokenuri noi —
// kill-switch-ul cerut de Articolul 14 (supervizare umană). Pachetul
// identity nu importă compliance; orice implementare care satisface
// această interfață (duck typing) poate fi conectată din main.go.
package identity

// SuspensionChecker decide dacă un agent este suspendat de un operator.
// Al doilea rezultat este motivul suspendării, util în mesajele de eroare
// și în jurnalizare.
type SuspensionChecker interface {
	IsSuspended(agentID string) (bool, string)
}

// NoopSuspensionChecker este implementarea implicită: niciun agent nu
// este vreodată suspendat. Folosită când nicio implementare reală nu
// este conectată.
type NoopSuspensionChecker struct{}

func (NoopSuspensionChecker) IsSuspended(_ string) (bool, string) { return false, "" }
