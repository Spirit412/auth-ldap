// Package auth implements the authentication domain service: credential
// verification via LDAP, token pair issuance, refresh rotation and logout.
package auth

import (
	"errors"
	"fmt"
	"net/http"
	"time"
)

// APIError is a sanitized, HTTP-mappable application error. It implements
// huma's StatusError, so it is rendered as RFC 9457 application/problem+json
// (S-15). Detail strings never contain internal facts (DNs, hostnames,
// stack traces) — only client-actionable information.
type APIError struct {
	Status     int
	Detail     string
	RetryAfter time.Duration // non-zero -> Retry-After header
}

func (e *APIError) Error() string  { return e.Detail }
func (e *APIError) GetStatus() int { return e.Status }

func (e *APIError) Title() string {
	switch e.Status {
	case http.StatusBadRequest:
		return "Bad Request"
	case http.StatusUnauthorized:
		return "Unauthorized"
	case http.StatusForbidden:
		return "Forbidden"
	case http.StatusNotFound:
		return "Not Found"
	case http.StatusTooManyRequests:
		return "Too Many Requests"
	case http.StatusServiceUnavailable:
		return "Service Unavailable"
	}
	return http.StatusText(e.Status)
}

// Common constructors — the ONLY error shapes that cross the API boundary.
func ErrInvalidCredentials() *APIError {
	// Identical for "no such user" and "wrong password" (S-08).
	return &APIError{Status: http.StatusUnauthorized, Detail: "invalid username or password"}
}

func ErrInvalidToken(detail string) *APIError {
	if detail == "" {
		detail = "invalid or expired token"
	}
	return &APIError{Status: http.StatusUnauthorized, Detail: detail}
}

func ErrForbidden() *APIError {
	return &APIError{Status: http.StatusForbidden, Detail: "insufficient permissions"}
}

func ErrNotFound(detail string) *APIError {
	return &APIError{Status: http.StatusNotFound, Detail: detail}
}

func ErrBadRequest(detail string) *APIError {
	return &APIError{Status: http.StatusBadRequest, Detail: detail}
}

func ErrRateLimited(retryAfter time.Duration) *APIError {
	return &APIError{
		Status:     http.StatusTooManyRequests,
		Detail:     fmt.Sprintf("rate limit exceeded, retry after %d seconds", int(retryAfter.Seconds())+1),
		RetryAfter: retryAfter,
	}
}

// ErrUnavailable is the fail-closed answer (S-07): dependencies down ->
// 503, never pass through.
func ErrUnavailable() *APIError {
	return &APIError{Status: http.StatusServiceUnavailable, Detail: "authentication service temporarily unavailable"}
}

// IsReplay reports whether err is (or wraps) a session replay signal.
func IsReplay(err error) bool { return errors.Is(err, errReplay) }

// errReplay internal marker; mapped to a generic 401 outside (a replay
// must be indistinguishable from any other invalid token, S-08).
var errReplay = errors.New("replay")
