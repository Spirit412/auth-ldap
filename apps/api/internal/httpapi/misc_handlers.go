package httpapi

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"aps.local/apps/api/internal/auth"
	"aps.local/apps/api/internal/jwks"
)

// --- JWKS (F-07, S-11) -------------------------------------------------------

type jwksInput struct{}

type jwksOutput struct {
	Body struct {
		Keys []jwks.JWK `json:"keys"`
	}
}

func registerPublic(api huma.API, d Deps) {
	huma.Register(api, huma.Operation{
		OperationID: "getJwks",
		Method:      http.MethodGet,
		Path:        "/.well-known/jwks.json",
		Summary:     "JSON Web Key Set for local JWT verification",
		Description: "Publishes the active signing key (by kid) and previous keys during rotation grace. Clients verify access tokens locally without calling APS.",
		Tags:        []string{"discovery"},
	}, func(ctx context.Context, _ *jwksInput) (*jwksOutput, error) {
		keys, err := d.Keys.Keys()
		if err != nil {
			return nil, fail(ctx, err)
		}
		out := &jwksOutput{}
		out.Body.Keys = keys
		return out, nil
	})

	// --- health / ready (F-08, S-07) -----------------------------------------

	type healthInput struct{}
	type healthOutput struct {
		Body struct {
			Status string `json:"status"`
		}
	}
	huma.Register(api, huma.Operation{
		OperationID: "health",
		Method:      http.MethodGet,
		Path:        "/health",
		Summary:     "Liveness probe",
		Tags:        []string{"ops"},
	}, func(ctx context.Context, _ *healthInput) (*healthOutput, error) {
		out := &healthOutput{}
		out.Body.Status = "ok"
		return out, nil
	})

	type readyInput struct{}
	type readyOutput struct {
		Body struct {
			Status string            `json:"status"`
			Checks map[string]string `json:"checks"`
		}
	}
	huma.Register(api, huma.Operation{
		OperationID: "ready",
		Method:      http.MethodGet,
		Path:        "/ready",
		Summary:     "Readiness probe (LDAP + Redis + PostgreSQL)",
		Description: "Fail-closed: returns 503 unless every backend dependency answers, so an LB never routes logins to a degraded instance.",
		Tags:        []string{"ops"},
		Errors:      []int{http.StatusServiceUnavailable},
	}, func(ctx context.Context, _ *readyInput) (*readyOutput, error) {
		checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		out := &readyOutput{}
		out.Body.Checks = map[string]string{}
		err := d.Svc.Ready(checkCtx)
		if err == nil {
			out.Body.Status = "ready"
			out.Body.Checks["ldap"] = "ok"
			out.Body.Checks["redis"] = "ok"
			out.Body.Checks["postgres"] = "ok"
			return out, nil
		}
		// Distinguish which dependency failed without leaking internals:
		// Ready's error text is safe (component names only), but we keep the
		// problem detail generic per S-15.
		return nil, auth.ErrUnavailable()
	})
}

// redocHTML serves the ReDoc UI bound to /openapi.json (F-13).
func redocHTML(w http.ResponseWriter, r *http.Request) {
	const page = `<!DOCTYPE html>
<html>
  <head>
    <title>APS API — ReDoc</title>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <style>body { margin: 0; padding: 0; }</style>
  </head>
  <body>
    <redoc spec-url="/openapi.json" hide-download-button="false"></redoc>
    <script src="https://cdn.redoc.ly/redoc/latest/bundles/redoc.standalone.js"></script>
  </body>
</html>`
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_, _ = w.Write([]byte(page))
}
