// Package audit emits structured security events.
//
// S-09 / F-11: every event carries username, ip, user_agent, request_id,
// result and (when applicable) jti. Passwords and full tokens are NEVER
// logged — only jti references are.
//
// The request-scoped logger (with request_id) is installed by middleware
// via zerolog's WithContext; audit events pick it up from the request
// context, so each event is automatically correlated with the HTTP request.
package audit

import (
	"context"

	"github.com/rs/zerolog"
)

// Logger emits security events on the request-scoped zerolog logger.
type Logger struct{}

func New() *Logger { return &Logger{} }

func event(ctx context.Context) *zerolog.Event {
	return zerolog.Ctx(ctx).Info()
}

// Login records a login attempt outcome.
func (l *Logger) Login(ctx context.Context, username, ip, userAgent, result, jti string) {
	e := event(ctx)
	e.Str("event", "login").
		Str("username", username).
		Str("ip", ip).
		Str("user_agent", userAgent).
		Str("result", result)
	if jti != "" {
		e.Str("jti", jti)
	}
	e.Msg("login attempt")
}

// Refresh records a refresh-token rotation outcome.
func (l *Logger) Refresh(ctx context.Context, username, ip, userAgent, result, jti string) {
	e := event(ctx)
	e.Str("event", "refresh").
		Str("username", username).
		Str("ip", ip).
		Str("user_agent", userAgent).
		Str("result", result)
	if jti != "" {
		e.Str("jti", jti)
	}
	e.Msg("refresh token")
}

// Logout records a logout.
func (l *Logger) Logout(ctx context.Context, username, ip, userAgent, result, familyID string) {
	event(ctx).
		Str("event", "logout").
		Str("username", username).
		Str("ip", ip).
		Str("user_agent", userAgent).
		Str("result", result).
		Str("family_id", familyID).
		Msg("logout")
}

// SessionRevoked records an admin-forced session revocation.
func (l *Logger) SessionRevoked(ctx context.Context, actor, target, familyID, result string) {
	event(ctx).
		Str("event", "session_revoked").
		Str("actor", actor).
		Str("username", target).
		Str("family_id", familyID).
		Str("result", result).
		Msg("session revoked by admin")
}

// RateLimited records a rate-limit denial (S-06, S-13 — no request is sent
// to AD once the username limit is exhausted).
func (l *Logger) RateLimited(ctx context.Context, username, ip, scope string) {
	event(ctx).
		Str("event", "rate_limited").
		Str("username", username).
		Str("ip", ip).
		Str("scope", scope).
		Msg("rate limit exceeded")
}
