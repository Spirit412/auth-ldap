// Package httpapi wires the huma-typed HTTP surface of APS: auth flows,
// admin endpoints, JWKS publication, health probes and API documentation.
//
// Error contract (S-15): every failure is returned as *auth.APIError which
// huma renders as RFC 9457 application/problem+json with sanitized details.
package httpapi

import (
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/rs/zerolog"

	"aps.local/apps/api/internal/auth"
	"aps.local/apps/api/internal/jwks"
	"aps.local/apps/api/internal/metrics"
	"aps.local/apps/api/internal/middleware"
)

// CookieCfg controls the aps_refresh cookie (S-10).
type CookieCfg struct {
	Secure     bool   // Secure flag (default true)
	Domain     string // optional, host-only when empty
	RefreshTTL time.Duration
}

// Deps are all collaborators the router needs.
type Deps struct {
	Svc     *auth.Service
	Keys    *jwks.Keystore
	Logger  zerolog.Logger
	Met     *metrics.Metrics
	RealIP  *middleware.RealIP
	Cookie  CookieCfg
	Docs    bool // expose /docs + /openapi.json (F-13, DOCS_ENABLED)
	Version string
}

// NewRouter builds the full HTTP handler. The second return exposes the
// huma API (used by cmd/openapi to dump the generated spec).
func NewRouter(d Deps) (http.Handler, huma.API) {
	r := chi.NewRouter()

	// Order matters: overlay must wrap everything so handlers can set
	// headers (Retry-After) even on error responses; request id before the
	// logger; real IP before the logger (it logs the ip).
	r.Use(middleware.HeaderOverlayMiddleware)
	r.Use(d.RealIP.Middleware)
	r.Use(middleware.RequestID)
	r.Use(middleware.RequestLogger(d.Logger))
	r.Use(middleware.Recoverer)
	r.Use(middleware.Metrics(d.Met))

	humaCfg := huma.DefaultConfig("Auth Proxy Service (APS)", d.Version)
	humaCfg.OpenAPIPath = "" // disabled by default, enabled below with docs
	humaCfg.DocsPath = ""    // own ReDoc page is registered at chi level
	humaCfg.SchemasPath = "" // inline schemas
	if d.Docs {
		humaCfg.OpenAPIPath = "/openapi"
	}
	humaCfg.Info.Description = "Centralized AD LDAP authentication proxy issuing JWT pairs (access + rotating refresh) with JWKS publication."
	humaCfg.Components.SecuritySchemes = map[string]*huma.SecurityScheme{
		"bearerAuth": {
			Type:         "http",
			Scheme:       "bearer",
			BearerFormat: "JWT",
			Description:  "Access token issued by POST /api/v1/auth/login.",
		},
	}
	api := humachi.New(r, humaCfg)

	registerAuth(api, d)
	registerAdmin(api, d)
	registerPublic(api, d)

	// Prometheus scrape endpoint (F-09) — chi-level, not in the OpenAPI spec.
	r.Method(http.MethodGet, "/metrics", promhttp.Handler())

	if d.Docs {
		r.Get("/docs", redocHTML)
	}
	return r, api
}

// bearerSecurity is attached to protected operations for the OpenAPI docs.
var bearerSecurity = []map[string][]string{{"bearerAuth": {}}}
