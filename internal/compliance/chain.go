// Package compliance implementează registrul de conformitate al Nexus
// Trust Protocol: un lanț de înregistrări tamper-evident (fiecare
// înregistrare conține hash-ul celei precedente, ca un mini-blockchain
// local), scris doar prin adăugare (write-once / append-only), menit să
// satisfacă cerințele de trasabilitate ale Articolului 12 din EU AI Act.
//
// chain.go conține mecanismul de bază: Append, persistare pe disc și
// VerifyChain — verificarea de integritate pe care un auditor sau
// gateway-ul însuși (la pornire) o poate rula pentru a detecta orice
// modificare retroactivă a istoricului.
package compliance

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// genesisHash este "hash-ul precedent" al primei înregistrări din lanț —
// o valoare fixă, publică, fără nicio semnificație secretă; rolul ei este
// doar să dea fiecărei înregistrări (inclusiv primei) un prev_hash bine
// definit, astfel încât lanțul să poată fi verificat de la capăt.
const genesisHash = "nexus-trust-protocol-compliance-genesis-2026"

// Record este o singură înregistrare din lanțul de conformitate.
type Record struct {
	Sequence  int64     `json:"seq"`
	Timestamp time.Time `json:"timestamp"`
	Event     string    `json:"event"` // request_received | response_returned | request_rejected | agent_suspended | agent_resumed

	// ClaimedAgentID este antetul declarat (nesigur) de client;
	// VerifiedAgentID este identitatea confirmată criptografic. A le
	// păstra separat face vizibilă orice discrepanță — semnal util pentru
	// un auditor sau un sistem de detecție a anomaliilor.
	ClaimedAgentID  string `json:"claimed_agent_id,omitempty"`
	VerifiedAgentID string `json:"verified_agent_id,omitempty"`
	TaskID          string `json:"task_id,omitempty"`
	SPIFFEID        string `json:"spiffe_id,omitempty"`

	UpstreamName string `json:"upstream_name,omitempty"`
	Tool         string `json:"tool,omitempty"` // metoda JSON-RPC/MCP apelată, dacă există
	HTTPMethod   string `json:"http_method,omitempty"`
	Path         string `json:"path,omitempty"`

	// PromptSHA256 este digest-ul integral al corpului cererii — păstrat
	// întotdeauna, indiferent de trunchiere, ca dovadă de integritate.
	// PromptExcerpt este o copie (eventual trunchiată) a conținutului,
	// utilă pentru audit uman direct; PromptTruncated marchează explicit
	// dacă excerpt-ul nu reprezintă promptul integral.
	PromptSHA256     string `json:"prompt_sha256,omitempty"`
	PromptExcerpt    string `json:"prompt_excerpt,omitempty"`
	PromptTruncated  bool   `json:"prompt_truncated,omitempty"`
	PromptBytesTotal int    `json:"prompt_bytes_total,omitempty"`

	Decision   string `json:"decision,omitempty"` // allowed | rejected
	Reason     string `json:"reason,omitempty"`
	StatusCode int    `json:"status_code,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`

	CumulativeSpendUSDToday float64 `json:"cumulative_spend_usd_today,omitempty"`

	// Operator/SuspensionReason sunt populate doar pentru evenimentele
	// kill-switch (agent_suspended/agent_resumed) — vezi suspension.go.
	Operator         string `json:"operator,omitempty"`
	SuspensionReason string `json:"suspension_reason,omitempty"`

	PrevHash string `json:"prev_hash"`
	Hash     string `json:"hash"`
}

// Chain este lanțul de conformitate persistat pe disc.
type Chain struct {
	mu              sync.Mutex
	file            *os.File
	path            string
	lastHash        string
	seq             int64
	retentionMonths int
}

// OpenChain deschide (sau creează) fișierul lanțului la path. Dacă
// fișierul există deja, integritatea lui este verificată ÎNAINTE de a
// permite scrieri noi — un lanț corupt sau modificat retroactiv face ca
// OpenChain să returneze eroare, iar gateway-ul să refuze pornirea
// (fail-closed), în loc să continue tăcut peste o încălcare de
// conformitate deja produsă.
//
// retentionMonths este politica de retenție declarată (informativă —
// stocată ca metadată în configurație, nu impusă prin ștergere automată
// în această fază); apelantul (config.Validate) trebuie să garanteze
// retentionMonths >= 6, conform Articolului 12.
func OpenChain(path string, retentionMonths int) (*Chain, error) {
	if retentionMonths < 6 {
		return nil, fmt.Errorf("compliance: retenția minimă cerută de Articolul 12 este de 6 luni, am primit %d", retentionMonths)
	}

	lastSeq, lastHash, err := scanChain(path)
	if err != nil {
		return nil, fmt.Errorf("compliance: lanțul de conformitate %s a eșuat verificarea de integritate la pornire — posibilă modificare neautorizată: %w", path, err)
	}

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("compliance: nu pot deschide lanțul %s: %w", path, err)
	}

	return &Chain{
		file:            f,
		path:            path,
		lastHash:        lastHash,
		seq:             lastSeq,
		retentionMonths: retentionMonths,
	}, nil
}

// Close închide fișierul suport al lanțului.
func (c *Chain) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.file.Close()
}

// RetentionMonths returnează politica de retenție declarată.
func (c *Chain) RetentionMonths() int { return c.retentionMonths }

// Append adaugă o nouă înregistrare la lanț, completând automat
// Sequence, Timestamp, PrevHash și Hash. Scrierea este sincronizată pe
// disc (fsync) înainte de a reveni — o înregistrare de conformitate
// raportată ca salvată trebuie să fie efectiv durabilă.
func (c *Chain) Append(rec Record) (Record, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.seq++
	rec.Sequence = c.seq
	if rec.Timestamp.IsZero() {
		rec.Timestamp = time.Now().UTC()
	}
	rec.PrevHash = c.lastHash
	rec.Hash = computeHash(rec)

	line, err := json.Marshal(rec)
	if err != nil {
		return rec, fmt.Errorf("compliance: nu pot serializa înregistrarea: %w", err)
	}
	line = append(line, '\n')

	if _, err := c.file.Write(line); err != nil {
		return rec, fmt.Errorf("compliance: nu pot scrie în lanțul %s: %w", c.path, err)
	}
	if err := c.file.Sync(); err != nil {
		return rec, fmt.Errorf("compliance: nu pot sincroniza lanțul %s pe disc: %w", c.path, err)
	}

	c.lastHash = rec.Hash
	return rec, nil
}

// computeHash calculează hash-ul unei înregistrări pe baza conținutului
// ei (cu Hash golit) și a PrevHash deja stabilit — orice modificare a
// oricărui câmp, sau a poziției în lanț, schimbă acest hash.
func computeHash(rec Record) string {
	rec.Hash = ""
	b, _ := json.Marshal(rec)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// VerifyChain re-verifică integritatea unui lanț de pe disc, de la
// început, recalculând fiecare hash și confirmând înlănțuirea PrevHash.
// Returnează numărul de înregistrări verificate cu succes; dacă lanțul e
// rupt, returnează eroarea cu secvența la care s-a detectat problema.
func VerifyChain(path string) (validRecords int64, err error) {
	validRecords, _, err = scanChain(path)
	return validRecords, err
}

// scanChain este implementarea comună pentru OpenChain (verificare la
// pornire) și VerifyChain (verificare la cerere, ex. dintr-un API admin).
func scanChain(path string) (lastSeq int64, lastHash string, err error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, genesisHash, nil
		}
		return 0, "", fmt.Errorf("nu pot citi lanțul: %w", err)
	}
	defer f.Close()

	expectedPrev := genesisHash
	var seq int64

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec Record
		if err := json.Unmarshal(line, &rec); err != nil {
			return seq, "", fmt.Errorf("înregistrare ilizibilă la linia %d: %w", seq+1, err)
		}

		seq++
		if rec.Sequence != seq {
			return seq, "", fmt.Errorf("secvență neașteptată la linia %d (rec.seq=%d) — posibilă ștergere/reordonare", seq, rec.Sequence)
		}
		if rec.PrevHash != expectedPrev {
			return seq, "", fmt.Errorf("prev_hash invalid la secvența %d — lanțul a fost modificat", seq)
		}
		want := computeHash(rec)
		if want != rec.Hash {
			return seq, "", fmt.Errorf("hash invalid la secvența %d — conținutul înregistrării a fost modificat", seq)
		}
		expectedPrev = rec.Hash
	}
	if err := scanner.Err(); err != nil {
		return seq, "", fmt.Errorf("eroare la citirea lanțului: %w", err)
	}

	return seq, expectedPrev, nil
}
