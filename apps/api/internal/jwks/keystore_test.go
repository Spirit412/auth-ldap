package jwks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func newTestKeystore(t *testing.T) *Keystore {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := NewInMemory(key, "test-kid", "aps", "aps-clients")
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func accessClaims(sub string) *accessTestClaims {
	now := time.Now()
	return &accessTestClaims{
		Subject:   sub,
		Issuer:    "aps",
		Audience:  jwt.ClaimStrings{"aps-clients"},
		ExpiresAt: jwt.NewNumericDate(now.Add(time.Minute)),
		IssuedAt:  jwt.NewNumericDate(now),
	}
}

type accessTestClaims struct {
	jwt.RegisteredClaims
	Roles    []string `json:"roles"`
	TokenUse string   `json:"token_use"`
}

// S-05: sign with kid header; parse verifies iss/aud/exp and returns claims.
func TestSignAndParseRoundTrip(t *testing.T) {
	ks := newTestKeystore(t)
	c := accessClaims("alice")
	c.Roles = []string{"admin"}
	c.TokenUse = "access"

	tok, err := ks.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	var out accessTestClaims
	if err := ks.Parse(tok, &out); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if out.Subject != "alice" || out.TokenUse != "access" || len(out.Roles) != 1 {
		t.Fatalf("claims mismatch: %+v", out)
	}
}

// F-07 acceptance #8: kid in the JWT header must match the JWKS document,
// and the published JWK must verify the signature without APS.
func TestKidHeaderMatchesJWKS(t *testing.T) {
	ks := newTestKeystore(t)
	c := accessClaims("bob")
	c.TokenUse = "access"
	tok, err := ks.Sign(c)
	if err != nil {
		t.Fatal(err)
	}

	t0, _, err := jwt.NewParser().ParseUnverified(tok, &accessTestClaims{})
	if err != nil {
		t.Fatal(err)
	}
	if t0.Header["kid"] != "test-kid" {
		t.Fatalf("kid header = %v, want test-kid", t0.Header["kid"])
	}

	keys, err := ks.Keys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].Kid != "test-kid" || keys[0].Alg != "ES256" || keys[0].Kty != "EC" {
		t.Fatalf("unexpected JWKS: %+v", keys)
	}
	if keys[0].Crv != "P-256" || keys[0].X == "" || keys[0].Y == "" {
		t.Fatalf("EC JWK incomplete: %+v", keys[0])
	}
}

func TestParseRejectsTamperedToken(t *testing.T) {
	ks := newTestKeystore(t)
	c := accessClaims("bob")
	c.TokenUse = "access"
	tok, err := ks.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	// flip a payload byte
	spoiled := tok[:len(tok)-3] + "aaa"
	var out accessTestClaims
	if err := ks.Parse(spoiled, &out); err == nil {
		t.Fatal("expected error for tampered token")
	}
}

func TestParseRejectsUnknownKid(t *testing.T) {
	ks := newTestKeystore(t)
	other, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Sign with a different key but keep kid "test-kid" absent: missing kid
	// must be rejected (algorithm confusion guard).
	c := accessClaims("eve")
	c.TokenUse = "access"
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, c)
	tok.Header["kid"] = "rogue-kid"
	raw, err := tok.SignedString(other)
	if err != nil {
		t.Fatal(err)
	}
	var out accessTestClaims
	if err := ks.Parse(raw, &out); err == nil {
		t.Fatal("expected error for unknown kid")
	}
}

func TestParseRejectsExpired(t *testing.T) {
	ks := newTestKeystore(t)
	c := accessClaims("old")
	c.TokenUse = "access"
	c.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
	tok, err := ks.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	var out accessTestClaims
	if err := ks.Parse(tok, &out); err == nil {
		t.Fatal("expected error for expired token")
	}
}

// S-11: private key must be loaded from a PEM file (never inline).
func TestLoadRSAFromPEMFile(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "jwt.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(file, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	ks, err := Load(file, "rsa-kid", "", "aps", "aps-clients")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ks.Keys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 1 || keys[0].Alg != "RS256" || keys[0].Kid != "rsa-kid" || keys[0].N == "" || keys[0].E == "" {
		t.Fatalf("unexpected RSA JWKS: %+v", keys)
	}

	c := accessClaims("carol")
	c.TokenUse = "access"
	tok, err := ks.Sign(c)
	if err != nil {
		t.Fatal(err)
	}
	var out accessTestClaims
	if err := ks.Parse(tok, &out); err != nil {
		t.Fatalf("parse: %v", err)
	}
}

func TestLoadRejectsSmallRSAKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	file := filepath.Join(dir, "weak.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	if err := os.WriteFile(file, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(file, "kid", "", "aps", "aps-clients"); err == nil {
		t.Fatal("expected error for 1024-bit RSA key")
	}
}

func TestPreviousKeysPublishedInJWKS(t *testing.T) {
	oldKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	oldFile := filepath.Join(dir, "old-kid.pem")
	oldPub, err := x509.MarshalPKIXPublicKey(&oldKey.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(oldFile, pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: oldPub}), 0o644); err != nil {
		t.Fatal(err)
	}

	activeKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	activeFile := filepath.Join(dir, "new-kid.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(activeKey)})
	if err := os.WriteFile(activeFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}

	ks, err := Load(activeFile, "new-kid", dir, "aps", "aps-clients")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := ks.Keys()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("want active+previous keys, got %d", len(keys))
	}
	kids := map[string]bool{}
	for _, k := range keys {
		kids[k.Kid] = true
	}
	if !kids["new-kid"] || !kids["old-kid"] {
		t.Fatalf("kids missing: %+v", kids)
	}
}
