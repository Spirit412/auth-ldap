package middleware

import (
	"context"
	"net/http"
	"strings"

	"aps.local/apps/api/internal/auth"
	"aps.local/apps/api/internal/jwks"
)

type ctxClaims struct{}

// ClaimsFromContext returns the verified access-token claims.
func ClaimsFromContext(ctx context.Context) *auth.AccessClaims {
	if v, ok := ctx.Value(ctxClaims{}).(*auth.AccessClaims); ok {
		return v
	}
	return nil
}

// Auth verifies the Bearer access JWT (F-04/F-05 security gate).
// Fail-closed: missing/malformed/expired tokens and tokens whose token_use
// is not "access" (e.g. refresh tokens presented as access) are all 401.
func Auth(keys *jwks.Keystore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			h := r.Header.Get("Authorization")
			const prefix = "Bearer "
			if !strings.HasPrefix(h, prefix) {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			var claims auth.AccessClaims
			if err := keys.Parse(strings.TrimSpace(strings.TrimPrefix(h, prefix)), &claims); err != nil {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if claims.TokenUse != auth.UseAccess {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxClaims{}, &claims)))
		})
	}
}

// RequireAdmin rejects authenticated users without the admin role (S-12).
// 401 vs 403 distinction: no/invalid token -> 401 (Auth), valid token
// without role -> 403.
func RequireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims := ClaimsFromContext(r.Context())
		if claims == nil {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		for _, role := range claims.Roles {
			if role == "admin" {
				next.ServeHTTP(w, r)
				return
			}
		}
		http.Error(w, "forbidden", http.StatusForbidden)
	})
}
