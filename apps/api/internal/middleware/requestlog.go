package middleware

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog"

	"aps.local/apps/api/internal/metrics"
)

// RequestID: uses the incoming X-Request-Id (bounded length) or generates
// one; the id goes into the response header, the request context and the
// zerolog request logger (F-11 audit correlation).
func RequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-Id")
		if id == "" || len(id) > 64 {
			id = newRequestID()
		}
		w.Header().Set("X-Request-Id", id)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxRequestID{}, id)))
	})
}

type ctxRequestID struct{}

// RequestIDFromContext extracts the request id (audit, tests).
func RequestIDFromContext(ctx context.Context) string {
	if v, ok := ctx.Value(ctxRequestID{}).(string); ok {
		return v
	}
	return ""
}

func newRequestID() string {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return time.Now().UTC().Format("20060102150405.000000000")
	}
	return hex.EncodeToString(b)
}

// RequestLogger installs a request-scoped zerolog logger with request_id,
// method, path and client IP; on completion it logs status and duration.
// S-09: bodies are never logged.
func RequestLogger(base zerolog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			logger := base.With().
				Str("request_id", RequestIDFromContext(r.Context())).
				Str("method", r.Method).
				Str("path", r.URL.Path).
				Str("ip", RealIPFromContext(r.Context())).
				Logger()
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			r = r.WithContext(logger.WithContext(r.Context()))
			next.ServeHTTP(sw, r)
			logger.Info().
				Int("status", sw.status).
				Dur("duration", time.Since(start)).
				Msg("request")
		})
	}
}

// Recoverer converts panics into 500s without leaking stack traces (S-15).
func Recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				zerolog.Ctx(r.Context()).Error().
					Interface("panic", rec).
					Msg("panic recovered")
				http.Error(w, "internal server error", http.StatusInternalServerError)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// Metrics instruments every request with counters/latency (F-09).
func Metrics(m *metrics.Metrics) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(sw, r)
			route := r.URL.Path
			// Normalise the only parameterised path for metric cardinality.
			const sessPrefix = "/api/v1/auth/sessions/"
			const userPrefix = "/api/v1/users/"
			switch {
			case strings.HasPrefix(route, sessPrefix) && len(route) > len(sessPrefix):
				route = "/api/v1/auth/sessions/{id}"
			case strings.HasPrefix(route, userPrefix) && len(route) > len(userPrefix):
				route = "/api/v1/users/{id}"
			}
			m.HTTPRequests.WithLabelValues(r.Method, route, strconv.Itoa(sw.status)).Inc()
			m.HTTPDuration.WithLabelValues(r.Method, route).Observe(time.Since(start).Seconds())
		})
	}
}

// statusWriter captures the response status.
type statusWriter struct {
	http.ResponseWriter
	status int
	wrote  bool
}

func (w *statusWriter) WriteHeader(code int) {
	if !w.wrote {
		w.status = code
		w.wrote = true
	}
	w.ResponseWriter.WriteHeader(code)
}

// HeaderOverlay lets handlers (and huma's error writer) attach headers such
// as Retry-After to the response even when returning an error: handlers put
// values in the overlay via SetResponseHeader; the wrapper applies them at
// WriteHeader time.
type HeaderOverlay struct {
	http.ResponseWriter
	extra map[string][]string
}

func HeaderOverlayMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ov := &HeaderOverlay{ResponseWriter: w, extra: map[string][]string{}}
		next.ServeHTTP(ov, r.WithContext(context.WithValue(r.Context(), ctxHeaderOverlay{}, ov)))
	})
}

type ctxHeaderOverlay struct{}

// SetResponseHeader adds a header to the current response from a handler.
func SetResponseHeader(ctx context.Context, key, value string) {
	if ov, ok := ctx.Value(ctxHeaderOverlay{}).(*HeaderOverlay); ok && ov != nil {
		ov.extra[key] = append(ov.extra[key], value)
	}
}

func (h *HeaderOverlay) WriteHeader(code int) {
	for k, vs := range h.extra {
		for _, v := range vs {
			h.ResponseWriter.Header().Add(k, v)
		}
	}
	h.ResponseWriter.WriteHeader(code)
}
