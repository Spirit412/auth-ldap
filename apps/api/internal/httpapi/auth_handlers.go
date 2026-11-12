package httpapi

import (
	"context"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"

	"aps.local/apps/api/internal/auth"
	"aps.local/apps/api/internal/middleware"
	"aps.local/apps/api/internal/userstore"
)

const refreshCookieName = "aps_refresh"

// --- helpers ---------------------------------------------------------------

// fail converts an *auth.APIError into a huma-ready error, attaching the
// Retry-After header when the limiter produced one (S-06).
func fail(ctx context.Context, err error) error {
	if ae, ok := err.(*auth.APIError); ok {
		if ae.RetryAfter > 0 {
			secs := int(ae.RetryAfter.Seconds()) + 1
			middleware.SetResponseHeader(ctx, "Retry-After", itoa(secs))
		}
		return ae
	}
	return auth.ErrUnavailable()
}

func itoa(v int) string {
	if v < 10 {
		return string(rune('0' + v))
	}
	digits := ""
	for v > 0 {
		digits = string(rune('0'+v%10)) + digits
		v /= 10
	}
	return digits
}

// setRefreshCookie builds the aps_refresh Set-Cookie value (S-10):
// HttpOnly; Secure; SameSite=Strict; Path=/api/v1/auth.
func setRefreshCookie(d Deps, value string, maxAge int) *http.Cookie {
	return &http.Cookie{
		Name:     refreshCookieName,
		Value:    value,
		Path:     "/api/v1/auth",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   d.Cookie.Secure,
		SameSite: http.SameSiteStrictMode,
		Domain:   d.Cookie.Domain,
	}
}

// clearRefreshCookie expires the cookie on logout.
func clearRefreshCookie(d Deps) *http.Cookie {
	return setRefreshCookie(d, "", -1)
}

// cookieValue extracts a cookie value from the raw Cookie header.
func cookieValue(rawHeader, name string) string {
	for _, part := range strings.Split(rawHeader, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 && kv[0] == name {
			return kv[1]
		}
	}
	return ""
}

// bearerClaims verifies the Authorization header value and returns access
// claims. All checks fail-closed: missing header, bad token or a token with
// the wrong token_use are 401.
func bearerClaims(ctx context.Context, d Deps, authz string) (*auth.AccessClaims, error) {
	const prefix = "Bearer "
	if !strings.HasPrefix(authz, prefix) {
		return nil, auth.ErrInvalidToken("")
	}
	var claims auth.AccessClaims
	if err := d.Keys.Parse(strings.TrimSpace(strings.TrimPrefix(authz, prefix)), &claims); err != nil {
		return nil, auth.ErrInvalidToken("")
	}
	if claims.TokenUse != auth.UseAccess {
		return nil, auth.ErrInvalidToken("")
	}
	return &claims, nil
}

// requireAdmin asserts the caller holds the admin role (S-12).
func requireAdmin(claims *auth.AccessClaims) error {
	for _, r := range claims.Roles {
		if r == "admin" {
			return nil
		}
	}
	return auth.ErrForbidden()
}

// hasRefreshCookie reports whether the request carries the refresh cookie;
// if it does, POSTs must include the X-Requested-With header (S-10 anti-CSRF,
// SameSite=Strict is the first line, custom header is the second).
func antiCSRFCookieGuard(rawCookie, xRequestedWith string) error {
	if cookieValue(rawCookie, refreshCookieName) == "" {
		return nil // programmatic client without cookies: no CSRF surface
	}
	if xRequestedWith != "XMLHttpRequest" {
		return &auth.APIError{Status: http.StatusForbidden, Detail: "missing X-Requested-With header"}
	}
	return nil
}

// --- DTOs -------------------------------------------------------------------

type loginRequest struct {
	Username string `json:"username" minLength:"1" maxLength:"128" doc:"AD login name (sAMAccountName)"`
	Password string `json:"password" minLength:"1" maxLength:"256" format:"password" doc:"AD password; used for Bind only and never stored or logged"`
}

type LoginInput struct {
	Cookie         string `header:"Cookie" doc:"optional aps_refresh cookie"`
	XRequestedWith string `header:"X-Requested-With" doc:"set by browser clients (anti-CSRF)"`
	Body           loginRequest
}

type LoginOutput struct {
	Body      auth.Tokens
	SetCookie string `header:"Set-Cookie" doc:"aps_refresh (HttpOnly, Secure, SameSite=Strict, Path=/api/v1/auth)"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token,omitempty" doc:"refresh token; required for programmatic clients, optional when the aps_refresh cookie is present"`
}

type RefreshInput struct {
	Cookie         string `header:"Cookie" doc:"aps_refresh cookie (browser clients)"`
	XRequestedWith string `header:"X-Requested-With" doc:"required when the cookie is used"`
	// Body is optional: browser clients refresh via the HttpOnly cookie and
	// send an empty POST body.
	Body *refreshRequest
}

type RefreshOutput struct {
	Body      auth.Tokens
	SetCookie string `header:"Set-Cookie" doc:"rotated aps_refresh"`
}

type LogoutInput struct {
	Authorization  string `header:"Authorization" required:"true"`
	Cookie         string `header:"Cookie" doc:"aps_refresh cookie to clear"`
	XRequestedWith string `header:"X-Requested-With"`
}

type LogoutOutput struct {
	Status    int    `json:"-"`
	SetCookie string `header:"Set-Cookie" doc:"expired aps_refresh"`
}

type MeInput struct {
	Authorization string `header:"Authorization" required:"true"`
}

type MeOutput struct {
	Body userstore.User
}

func registerAuth(api huma.API, d Deps) {
	huma.Register(api, huma.Operation{
		OperationID: "login",
		Method:      http.MethodPost,
		Path:        "/api/v1/auth/login",
		Summary:     "Authenticate against AD and issue a token pair",
		Description: "Verifies credentials via LDAPS bind. Rate limit: 5 attempts / 15 min per IP+username (S-06). User enumeration is prevented (S-08). The refresh token is returned in the body and set as an HttpOnly cookie (S-10).",
		Tags:        []string{"auth"},
		Errors:      []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests, http.StatusServiceUnavailable},
	}, func(ctx context.Context, in *LoginInput) (*LoginOutput, error) {
		if err := antiCSRFCookieGuard(in.Cookie, in.XRequestedWith); err != nil {
			return nil, fail(ctx, err)
		}
		ip := middleware.RealIPFromContext(ctx)
		tokens, _, err := d.Svc.Login(ctx, in.Body.Username, in.Body.Password, ip, userAgent(ctx))
		if err != nil {
			return nil, fail(ctx, err)
		}
		return &LoginOutput{
			Body:      *tokens,
			SetCookie: setRefreshCookie(d, tokens.RefreshToken, int(d.Cookie.RefreshTTL.Seconds())).String(),
		}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "refresh",
		Method:      http.MethodPost,
		Path:        "/api/v1/auth/refresh",
		Summary:     "Rotate the refresh token and issue a new pair",
		Description: "One-time use: replaying an already-used refresh token revokes the whole session family (S-04). Rate limit: 10/min per user (S-06). Roles are re-read from AD on every refresh (S-12).",
		Tags:        []string{"auth"},
		Errors:      []int{http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden, http.StatusTooManyRequests, http.StatusServiceUnavailable},
	}, func(ctx context.Context, in *RefreshInput) (*RefreshOutput, error) {
		if err := antiCSRFCookieGuard(in.Cookie, in.XRequestedWith); err != nil {
			return nil, fail(ctx, err)
		}
		raw := ""
		if in.Body != nil {
			raw = in.Body.RefreshToken
		}
		if raw == "" {
			raw = cookieValue(in.Cookie, refreshCookieName)
		}
		if raw == "" {
			return nil, fail(ctx, auth.ErrBadRequest("refresh_token is required in body or aps_refresh cookie"))
		}
		ip := middleware.RealIPFromContext(ctx)
		tokens, _, err := d.Svc.Refresh(ctx, raw, ip, userAgent(ctx))
		if err != nil {
			return nil, fail(ctx, err)
		}
		return &RefreshOutput{
			Body:      *tokens,
			SetCookie: setRefreshCookie(d, tokens.RefreshToken, int(d.Cookie.RefreshTTL.Seconds())).String(),
		}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID:   "logout",
		Method:        http.MethodPost,
		Path:          "/api/v1/auth/logout",
		Summary:       "Revoke the current session and clear the refresh cookie",
		DefaultStatus: http.StatusNoContent,
		Security:      bearerSecurity,
		Tags:          []string{"auth"},
		Errors:        []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusServiceUnavailable},
	}, func(ctx context.Context, in *LogoutInput) (*LogoutOutput, error) {
		if err := antiCSRFCookieGuard(in.Cookie, in.XRequestedWith); err != nil {
			return nil, fail(ctx, err)
		}
		claims, err := bearerClaims(ctx, d, in.Authorization)
		if err != nil {
			return nil, fail(ctx, err)
		}
		if err := d.Svc.Logout(ctx, claims, middleware.RealIPFromContext(ctx), userAgent(ctx)); err != nil {
			// Revocation failure must not leak internals; report 503.
			return nil, fail(ctx, auth.ErrUnavailable())
		}
		return &LogoutOutput{Status: http.StatusNoContent, SetCookie: clearRefreshCookie(d).String()}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "me",
		Method:      http.MethodGet,
		Path:        "/api/v1/auth/me",
		Summary:     "Own profile from the local user cache (no LDAP call)",
		Security:    bearerSecurity,
		Tags:        []string{"auth"},
		Errors:      []int{http.StatusUnauthorized, http.StatusServiceUnavailable},
	}, func(ctx context.Context, in *MeInput) (*MeOutput, error) {
		claims, err := bearerClaims(ctx, d, in.Authorization)
		if err != nil {
			return nil, fail(ctx, err)
		}
		u, err := d.Svc.Me(ctx, claims)
		if err != nil {
			return nil, fail(ctx, err)
		}
		return &MeOutput{Body: *u}, nil
	})
}

// userAgent extracts the User-Agent for audit records. huma input structs
// carry it as a header field on ops that need it; here we read it from the
// huma context request headers uniformly.
func userAgent(ctx context.Context) string {
	type headerGetter interface {
		Header(string) string
	}
	// huma.Context exposes header access; the value lands in the request
	// context via middleware only for logging — read it via huma ctx.
	if hc, ok := ctx.(headerGetter); ok {
		return truncate(hc.Header("User-Agent"), 256)
	}
	return ""
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
