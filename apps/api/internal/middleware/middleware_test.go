package middleware

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"aps.local/apps/api/internal/auth"
	"aps.local/apps/api/internal/jwks"
)

func newKeystore(t *testing.T) *jwks.Keystore {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ks, err := jwks.NewInMemory(key, "kid", "aps", "aps-clients")
	if err != nil {
		t.Fatal(err)
	}
	return ks
}

func accessFor(t *testing.T, ks *jwks.Keystore, sub string, roles []string) string {
	t.Helper()
	now := time.Now()
	c := auth.AccessClaims{TokenUse: auth.UseAccess, Roles: roles, FamilyID: "fam"}
	c.Subject = sub
	c.Issuer = "aps"
	c.Audience = jwt.ClaimStrings{"aps-clients"}
	c.IssuedAt = jwt.NewNumericDate(now)
	c.ExpiresAt = jwt.NewNumericDate(now.Add(time.Minute))
	tok, err := ks.Sign(&c)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func TestRealIPTrustedProxy(t *testing.T) {
	m, err := NewRealIP([]string{"10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}
	var got string
	h := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = RealIPFromContext(r.Context())
	}))

	// Trusted proxy: XFF honoured.
	req := httptest.NewRequest("POST", "/", nil)
	req.RemoteAddr = "10.0.0.9:55555"
	req.Header.Set("X-Forwarded-For", "203.0.113.7, 10.0.0.1")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if got != "203.0.113.7" {
		t.Fatalf("real ip = %q, want 203.0.113.7", got)
	}

	// Untrusted peer: header ignored (spoof protection).
	req = httptest.NewRequest("POST", "/", nil)
	req.RemoteAddr = "192.168.5.5:55555"
	req.Header.Set("X-Forwarded-For", "203.0.113.7")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if got != "192.168.5.5" {
		t.Fatalf("real ip = %q, want 192.168.5.5 (peer)", got)
	}

	// No header: peer address passes through.
	req = httptest.NewRequest("POST", "/", nil)
	req.RemoteAddr = "10.9.9.9:1"
	h.ServeHTTP(httptest.NewRecorder(), req)
	if got != "10.9.9.9" {
		t.Fatalf("real ip = %q, want 10.9.9.9", got)
	}
}

func TestAuthMiddleware(t *testing.T) {
	ks := newKeystore(t)
	tok := accessFor(t, ks, "alice", []string{"admin"})

	var claims *auth.AccessClaims
	handler := Auth(ks)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims = ClaimsFromContext(r.Context())
		w.WriteHeader(200)
	}))

	// valid token passes
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 200 || claims == nil || claims.Subject != "alice" {
		t.Fatalf("valid bearer rejected: code=%d claims=%v", rec.Code, claims)
	}

	// missing token -> 401
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 401 {
		t.Fatalf("missing bearer must be 401, got %d", rec.Code)
	}

	// refresh token as bearer -> 401 (token_use check)
	now := time.Now()
	c := auth.RefreshClaims{TokenUse: auth.UseRefresh, FamilyID: "f"}
	c.Subject = "alice"
	c.Issuer = "aps"
	c.Audience = jwt.ClaimStrings{"aps-clients"}
	c.IssuedAt = jwt.NewNumericDate(now)
	c.ExpiresAt = jwt.NewNumericDate(now.Add(time.Minute))
	rtok, err := ks.Sign(&c)
	if err != nil {
		t.Fatal(err)
	}
	req = httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+rtok)
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != 401 {
		t.Fatalf("refresh as bearer must be 401, got %d", rec.Code)
	}
}

func TestRequireAdmin(t *testing.T) {
	called := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true })

	// admin passes
	ctx := context.WithValue(context.Background(), ctxClaims{}, &auth.AccessClaims{Roles: []string{"admin"}})
	req := httptest.NewRequest("GET", "/", nil).WithContext(ctx)
	RequireAdmin(next).ServeHTTP(httptest.NewRecorder(), req)
	if !called {
		t.Fatal("admin must pass")
	}

	// no role -> 403
	called = false
	ctx = context.WithValue(context.Background(), ctxClaims{}, &auth.AccessClaims{Roles: []string{}})
	rec := httptest.NewRecorder()
	RequireAdmin(next).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil).WithContext(ctx))
	if called || rec.Code != 403 {
		t.Fatalf("non-admin must be 403, got code=%d called=%v", rec.Code, called)
	}

	// no claims -> 401
	rec = httptest.NewRecorder()
	RequireAdmin(next).ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != 401 {
		t.Fatalf("no claims must be 401, got %d", rec.Code)
	}
}

func TestHeaderOverlayRetryAfter(t *testing.T) {
	rec := httptest.NewRecorder()
	var overlay *HeaderOverlay
	h := HeaderOverlayMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		overlay = w.(*HeaderOverlay)
		SetResponseHeader(r.Context(), "Retry-After", "42")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	req := httptest.NewRequest("GET", "/", nil)
	h.ServeHTTP(rec, req)
	_ = overlay
	if rec.Header().Get("Retry-After") != "42" {
		t.Fatalf("Retry-After = %q, want 42", rec.Header().Get("Retry-After"))
	}
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("status = %d", rec.Code)
	}
}

func TestRequestID(t *testing.T) {
	var id string
	h := RequestID(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id = RequestIDFromContext(r.Context())
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if id == "" {
		t.Fatal("request id must be generated")
	}
	if rec.Header().Get("X-Request-Id") != id {
		t.Fatal("request id must be echoed in the response header")
	}
}
