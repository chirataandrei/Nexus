// Package keystore persists Ed25519 signing keys on disk and derives a
// stable key ID (kid) from the public key, so a key survives restarts
// and can be rotated: tokens and ledger anchors carry the kid of the key
// that signed them, and verifiers look the matching public key up.
package keystore

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// KeyID returns the kid for a public key: the first 16 hex characters of
// its SHA-256 digest.
func KeyID(pub ed25519.PublicKey) string {
	sum := sha256.Sum256(pub)
	return hex.EncodeToString(sum[:8])
}

type keyFile struct {
	KID        string `json:"kid"`
	PrivateKey string `json:"private_key"` // base64 (std) of the 64-byte Ed25519 private key
}

// LoadOrCreate reads the key at path, or generates and stores a new one
// (mode 0600, created atomically) if the file doesn't exist. The second
// return value reports whether a key was created.
func LoadOrCreate(path string) (priv ed25519.PrivateKey, created bool, err error) {
	raw, err := os.ReadFile(path)
	if err == nil {
		priv, err = parse(raw)
		return priv, false, err
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, fmt.Errorf("keystore: cannot read %s: %w", path, err)
	}

	_, priv, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, false, fmt.Errorf("keystore: cannot generate key: %w", err)
	}
	if err := write(path, priv); err != nil {
		return nil, false, err
	}
	return priv, true, nil
}

func parse(raw []byte) (ed25519.PrivateKey, error) {
	var f keyFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, fmt.Errorf("keystore: invalid key file: %w", err)
	}
	b, err := base64.StdEncoding.DecodeString(f.PrivateKey)
	if err != nil || len(b) != ed25519.PrivateKeySize {
		return nil, errors.New("keystore: key file does not hold a valid Ed25519 private key")
	}
	priv := ed25519.PrivateKey(b)
	if want := KeyID(priv.Public().(ed25519.PublicKey)); f.KID != want {
		return nil, fmt.Errorf("keystore: kid %q does not match the key (%q) — file was edited", f.KID, want)
	}
	return priv, nil
}

func write(path string, priv ed25519.PrivateKey) error {
	data, err := json.MarshalIndent(keyFile{
		KID:        KeyID(priv.Public().(ed25519.PublicKey)),
		PrivateKey: base64.StdEncoding.EncodeToString(priv),
	}, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("keystore: %w", err)
	}
	// O_EXCL: never overwrite a key that appeared in the meantime.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("keystore: cannot create %s: %w", path, err)
	}
	if _, err := f.Write(append(data, '\n')); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// PublicKeySet maps kid -> public key. It is what verifiers use during
// rotation: the current key plus any retired keys still allowed to verify
// tokens/anchors issued before the rotation.
type PublicKeySet map[string]ed25519.PublicKey

// Add registers a public key under its derived kid.
func (s PublicKeySet) Add(pub ed25519.PublicKey) { s[KeyID(pub)] = pub }

// LoadPublicKeys reads a JSON file {"<kid>": "<base64 public key>"} of
// retired public keys. A missing path ("") yields an empty set.
func LoadPublicKeys(path string) (PublicKeySet, error) {
	set := PublicKeySet{}
	if path == "" {
		return set, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("keystore: cannot read %s: %w", path, err)
	}
	var m map[string]string
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, fmt.Errorf("keystore: invalid JSON in %s: %w", path, err)
	}
	for kid, b64 := range m {
		b, err := base64.StdEncoding.DecodeString(b64)
		if err != nil || len(b) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("keystore: %s: kid %q is not a valid Ed25519 public key", path, kid)
		}
		pub := ed25519.PublicKey(b)
		if KeyID(pub) != kid {
			return nil, fmt.Errorf("keystore: %s: kid %q does not match its key", path, kid)
		}
		set[kid] = pub
	}
	return set, nil
}

// EncodePublic returns the base64 form used in retired-key files.
func EncodePublic(pub ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(pub) }
