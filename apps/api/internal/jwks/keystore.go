// Package jwks implements the signing keystore: it loads the private key
// from a file (never from env, S-11), signs access/refresh JWTs with a
// kid header, verifies tokens against the active and previous keys, and
// renders the JWKS document published at /.well-known/jwks.json (F-07).
//
// Supported key types: RSA (RS256) and ECDSA P-256/P-384/P-521
// (ES256/ES384/ES512). Rotation: JWT_PREV_KEYS_DIR holds previous PUBLIC
// keys named <kid>.pem; they remain in JWKS for the grace period and are
// still accepted for verification so that outstanding access tokens
// survive a key rollover.
package jwks

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrNoKeyForKid = errors.New("no key for kid")
	ErrBadToken    = errors.New("invalid token")
)

// Key is one public key in the store.
type Key struct {
	KID string
	Alg string
	Pub crypto.PublicKey
}

// Keystore holds the active signing key plus optional previous public keys.
type Keystore struct {
	active   Key
	private  crypto.Signer
	previous []Key
	issuer   string
	audience string
}

// Load reads the active private key and optional previous public keys.
// issuer/audience are enforced on every Parse.
func Load(privateKeyFile, kid, prevKeysDir, issuer, audience string) (*Keystore, error) {
	if kid == "" {
		return nil, fmt.Errorf("jwt key id is empty")
	}
	priv, err := loadPrivate(privateKeyFile)
	if err != nil {
		return nil, err
	}

	var active Key
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		if k.N.BitLen() < 2048 {
			return nil, fmt.Errorf("rsa key too small: %d bits, need >= 2048", k.N.BitLen())
		}
		active = Key{KID: kid, Alg: "RS256", Pub: k.Public()}
	case *ecdsa.PrivateKey:
		alg, err := ecdsaAlg(k.Curve)
		if err != nil {
			return nil, err
		}
		active = Key{KID: kid, Alg: alg, Pub: k.Public()}
	default:
		return nil, fmt.Errorf("unsupported private key type %T (need RSA or ECDSA)", priv)
	}

	ks := &Keystore{active: active, private: priv, issuer: issuer, audience: audience}
	if prevKeysDir != "" {
		entries, err := os.ReadDir(prevKeysDir)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("read JWT_PREV_KEYS_DIR: %w", err)
		}
		for _, e := range entries {
			name := e.Name()
			if e.IsDir() || (!strings.HasSuffix(name, ".pem") && !strings.HasSuffix(name, ".pub")) {
				continue
			}
			prevKID := strings.TrimSuffix(strings.TrimSuffix(name, ".pem"), ".pub")
			if prevKID == kid {
				continue // never publish/accept the same kid twice
			}
			pub, err := loadPublic(filepath.Join(prevKeysDir, name))
			if err != nil {
				return nil, fmt.Errorf("prev key %s: %w", name, err)
			}
			alg := ""
			switch p := pub.(type) {
			case *rsa.PublicKey:
				alg = "RS256"
			case *ecdsa.PublicKey:
				alg, err = ecdsaAlg(p.Curve)
				if err != nil {
					return nil, fmt.Errorf("prev key %s: %w", name, err)
				}
			}
			ks.previous = append(ks.previous, Key{KID: prevKID, Alg: alg, Pub: pub})
		}
	}
	return ks, nil
}

// NewInMemory builds a keystore from an in-memory ECDSA P-256 key — used by
// tests and the openapi dumper (no filesystem access needed).
func NewInMemory(priv *ecdsa.PrivateKey, kid, issuer, audience string) (*Keystore, error) {
	alg, err := ecdsaAlg(priv.Curve)
	if err != nil {
		return nil, err
	}
	return &Keystore{
		active:   Key{KID: kid, Alg: alg, Pub: priv.Public()},
		private:  priv,
		issuer:   issuer,
		audience: audience,
	}, nil
}

func ecdsaAlg(c elliptic.Curve) (string, error) {
	switch c {
	case elliptic.P256():
		return "ES256", nil
	case elliptic.P384():
		return "ES384", nil
	case elliptic.P521():
		return "ES512", nil
	}
	return "", fmt.Errorf("unsupported ec curve: %v", c)
}

// Sign claims into a compact JWT with the active kid in the header (S-05).
func (ks *Keystore) Sign(claims jwt.Claims) (string, error) {
	method := jwt.GetSigningMethod(ks.active.Alg)
	if method == nil {
		return "", fmt.Errorf("unknown signing method %s", ks.active.Alg)
	}
	token := jwt.NewWithClaims(method, claims)
	token.Header["kid"] = ks.active.KID
	return token.SignedString(ks.private)
}

// Parse verifies signature (against active or previous keys by kid),
// expiry and iss/aud. alg is constrained to the pinned key algorithm,
// mitigating algorithm-confusion attacks.
func (ks *Keystore) Parse(tokenString string, claims jwt.Claims) error {
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{ks.active.Alg}),
		jwt.WithIssuer(ks.issuer),
		jwt.WithAudience(ks.audience),
		jwt.WithExpirationRequired(),
		jwt.WithLeeway(30*time.Second),
	)
	_, err := parser.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		if kid == "" {
			return nil, fmt.Errorf("%w: missing kid", ErrBadToken)
		}
		if kid == ks.active.KID {
			return ks.active.Pub, nil
		}
		for i := range ks.previous {
			if ks.previous[i].KID == kid {
				return ks.previous[i].Pub, nil
			}
		}
		return nil, ErrNoKeyForKid
	})
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBadToken, err)
	}
	return nil
}

// JWK is one public key in the JSON Web Key Set (typed for OpenAPI docs).
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n,omitempty"`   // RSA modulus (base64url)
	E   string `json:"e,omitempty"`   // RSA exponent (base64url)
	Crv string `json:"crv,omitempty"` // EC curve
	X   string `json:"x,omitempty"`   // EC x (base64url)
	Y   string `json:"y,omitempty"`   // EC y (base64url)
}

// Keys renders the public key set: the active key plus previous keys
// published for the rotation grace period (S-11).
func (ks *Keystore) Keys() ([]JWK, error) {
	jwk, err := renderJWK(ks.active)
	if err != nil {
		return nil, err
	}
	keys := []JWK{jwk}
	for _, k := range ks.previous {
		j, err := renderJWK(k)
		if err != nil {
			return nil, err
		}
		keys = append(keys, j)
	}
	return keys, nil
}

// JWKS renders the full JSON document served at /.well-known/jwks.json.
func (ks *Keystore) JWKS() (map[string]any, error) {
	keys, err := ks.Keys()
	if err != nil {
		return nil, err
	}
	return map[string]any{"keys": keys}, nil
}

func renderJWK(k Key) (JWK, error) {
	jwk := JWK{
		Use: "sig",
		Alg: k.Alg,
		Kid: k.KID,
	}
	switch pub := k.Pub.(type) {
	case *rsa.PublicKey:
		jwk.Kty = "RSA"
		jwk.N = base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
		jwk.E = base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	case *ecdsa.PublicKey:
		jwk.Kty = "EC"
		switch pub.Curve {
		case elliptic.P256():
			jwk.Crv = "P-256"
		case elliptic.P384():
			jwk.Crv = "P-384"
		case elliptic.P521():
			jwk.Crv = "P-521"
		default:
			return jwk, fmt.Errorf("unsupported ec curve")
		}
		size := (pub.Curve.Params().BitSize + 7) / 8
		x := pub.X.FillBytes(make([]byte, size))
		y := pub.Y.FillBytes(make([]byte, size))
		jwk.X = base64.RawURLEncoding.EncodeToString(x)
		jwk.Y = base64.RawURLEncoding.EncodeToString(y)
	default:
		return jwk, fmt.Errorf("unsupported public key type %T", k.Pub)
	}
	return jwk, nil
}

// --- PEM loading ---------------------------------------------------------

func loadPrivate(file string) (crypto.Signer, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", file, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block", file)
	}
	// Try PKCS#8, then PKCS#1 (RSA) and SEC1 (EC) — accepted key encodings.
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if s, ok := key.(crypto.Signer); ok {
			return s, nil
		}
		return nil, fmt.Errorf("%s: key of type %T cannot sign", file, key)
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("%s: unsupported private key format", file)
}

func loadPublic(file string) (crypto.PublicKey, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", file, err)
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil, fmt.Errorf("%s: no PEM block", file)
	}
	if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
		return pub, nil
	}
	if pub, err := x509.ParsePKCS1PublicKey(block.Bytes); err == nil {
		return pub, nil
	}
	return nil, fmt.Errorf("%s: unsupported public key format", file)
}

// MarshalJWKS is a helper for handlers returning raw JSON.
func MarshalJWKS(doc map[string]any) (json.RawMessage, error) {
	b, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	return b, nil
}
