package auth

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"aps.local/apps/api/internal/audit"
	"aps.local/apps/api/internal/jwks"
	"aps.local/apps/api/internal/ldap"
	"aps.local/apps/api/internal/metrics"
	"aps.local/apps/api/internal/session"
	"aps.local/apps/api/internal/userstore"
)

// Claims carried by both token kinds (S-05). token_use prevents confusion
// between access and refresh tokens.
type tokenUse string

const (
	UseAccess  tokenUse = "access"
	UseRefresh tokenUse = "refresh"
)

// AccessClaims is the payload of the 15-minute access JWT.
type AccessClaims struct {
	jwt.RegisteredClaims
	TokenUse    tokenUse `json:"token_use"`
	Roles       []string `json:"roles"`
	FamilyID    string   `json:"fid"`
	DisplayName string   `json:"name,omitempty"`
	Email       string   `json:"email,omitempty"`
}

// RefreshClaims is the payload of the long-lived refresh JWT. Only the jti
// is trusted as a Redis key; everything else is re-checked against the
// stored session record.
type RefreshClaims struct {
	jwt.RegisteredClaims
	TokenUse tokenUse `json:"token_use"`
	FamilyID string   `json:"fid"`
}

// Tokens is the response payload for login/refresh.
type Tokens struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int64  `json:"expires_in"` // access token TTL, seconds
}

// Directory is the LDAP capability the service needs.
type Directory interface {
	Authenticate(username, password string) (*ldap.User, error)
	UserByDN(dn string) (*ldap.User, error)
	Ping() error
}

// SessionStore is the refresh-session persistence capability.
type SessionStore interface {
	Create(ctx context.Context, sess *session.Session) error
	Rotate(ctx context.Context, familyID, oldJTI string, newSess *session.Session) error
	RevokeFamily(ctx context.Context, familyID string) error
	RevokeUserSessions(ctx context.Context, username string) error
	GetFamily(ctx context.Context, familyID string) (*session.SessionInfo, error)
	ListByUser(ctx context.Context, username string, limit int, cursor string) ([]session.SessionInfo, string, error)
	ListAll(ctx context.Context, limit int, cursor string) ([]session.SessionInfo, string, error)
	Ping(ctx context.Context) error
}

// UserStore is the PostgreSQL profile-cache capability (GORM-backed).
type UserStore interface {
	UpsertFromLogin(ctx context.Context, u *ldap.User) (*userstore.User, error)
	GetActiveByUsername(ctx context.Context, username string) (*userstore.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*userstore.User, error)
	List(ctx context.Context, f userstore.ListFilter) ([]userstore.User, string, error)
	SoftDelete(ctx context.Context, id uuid.UUID) error
	Ping(ctx context.Context) error
}

// RateLimiter guards login and refresh endpoints (S-06).
type RateLimiter interface {
	// AllowLogin: 5 / 15min per IP+username. Returns retry-after when denied.
	AllowLogin(ctx context.Context, ip, username string) (time.Duration, bool, error)
	// AllowRefresh: 10 / min per user id.
	AllowRefresh(ctx context.Context, userID string) (time.Duration, bool, error)
}

// Options holds service configuration.
type Options struct {
	Issuer       string
	Audience     string
	AdminGroupDN string // informational; role mapping lives in the ldap package
	AccessTTL    time.Duration
	RefreshTTL   time.Duration
	Now          func() time.Time // overridable in tests
}

// Service orchestrates authentication flows.
type Service struct {
	keys  *jwks.Keystore
	dir   Directory
	sess  SessionStore
	users UserStore
	lim   RateLimiter
	audit *audit.Logger
	met   *metrics.Metrics
	opt   Options
}

func NewService(keys *jwks.Keystore, dir Directory, sess SessionStore, users UserStore, lim RateLimiter,
	aud *audit.Logger, met *metrics.Metrics, opt Options) *Service {
	if opt.Now == nil {
		opt.Now = time.Now
	}
	return &Service{keys: keys, dir: dir, sess: sess, users: users, lim: lim, audit: aud, met: met, opt: opt}
}

func newID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		panic("crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b)
}

func (s *Service) now() time.Time { return s.opt.Now().UTC().Truncate(time.Second) }

// Login verifies credentials and issues the first token pair of a session.
func (s *Service) Login(ctx context.Context, username, password, ip, userAgent string) (*Tokens, *AccessClaims, error) {
	// S-06/S-13: check the limit BEFORE touching AD; once exhausted for a
	// username, no further bind attempts are sent (protects against
	// targeted AD lockout through APS).
	retry, ok, err := s.lim.AllowLogin(ctx, ip, username)
	if err != nil {
		s.met.LoginAttempts.WithLabelValues("error").Inc()
		return nil, nil, ErrUnavailable() // fail-closed on Redis errors
	}
	if !ok {
		s.met.LoginAttempts.WithLabelValues("rate_limited").Inc()
		s.audit.RateLimited(ctx, username, ip, "login")
		return nil, nil, ErrRateLimited(retry)
	}

	user, err := s.dir.Authenticate(username, password)
	if err != nil {
		switch {
		case err == ldap.ErrInvalidCredentials || err == ldap.ErrAmbiguousUser:
			s.met.LoginAttempts.WithLabelValues("invalid_credentials").Inc()
			s.audit.Login(ctx, username, ip, userAgent, "invalid_credentials", "")
			// Ambiguous users are reported exactly like bad passwords (S-08).
			return nil, nil, ErrInvalidCredentials()
		default:
			s.met.LoginAttempts.WithLabelValues("error").Inc()
			s.audit.Login(ctx, username, ip, userAgent, "error", "")
			return nil, nil, ErrUnavailable()
		}
	}

	// Persist/refresh the local profile copy (no password stored). The DB
	// is part of the fail-closed surface: an outage blocks login (S-07).
	if _, err := s.users.UpsertFromLogin(ctx, user); err != nil {
		s.met.LoginAttempts.WithLabelValues("error").Inc()
		s.audit.Login(ctx, username, ip, userAgent, "error", "")
		return nil, nil, ErrUnavailable()
	}

	tokens, claims, err := s.issue(ctx, user, ip, userAgent)
	if err != nil {
		s.met.LoginAttempts.WithLabelValues("error").Inc()
		s.audit.Login(ctx, username, ip, userAgent, "error", "")
		return nil, nil, ErrUnavailable()
	}
	s.met.LoginAttempts.WithLabelValues("success").Inc()
	s.audit.Login(ctx, username, ip, userAgent, "success", claims.ID)
	return tokens, claims, nil
}

// issue creates a session family, persists the refresh grant and signs both tokens.
func (s *Service) issue(ctx context.Context, user *ldap.User, ip, userAgent string) (*Tokens, *AccessClaims, error) {
	now := s.now()
	familyID := newID()
	jtiR := newID()
	jtiA := newID()

	// The refresh grant is stored FIRST; token signing happens after, so a
	// Redis outage cannot produce tokens without a server-side record.
	err := s.sess.Create(ctx, &session.Session{
		FamilyID:    familyID,
		JTI:         jtiR,
		Username:    user.Username,
		UserAgent:   userAgent,
		IP:          ip,
		CreatedAt:   now,
		Roles:       user.Roles,
		DN:          user.DN,
		DisplayName: user.DisplayName,
		Email:       user.Email,
	})
	if err != nil {
		return nil, nil, err
	}

	access, err := s.signAccess(user.Username, user.DisplayName, user.Email, user.Roles, familyID, jtiA, now, s.opt.AccessTTL)
	if err != nil {
		return nil, nil, err
	}
	refresh, err := s.signRefresh(user.Username, familyID, jtiR, now, s.opt.RefreshTTL)
	if err != nil {
		return nil, nil, err
	}

	claims := &AccessClaims{
		TokenUse:    UseAccess,
		Roles:       user.Roles,
		FamilyID:    familyID,
		DisplayName: user.DisplayName,
		Email:       user.Email,
		ID:          jtiA,
	}
	claims.Subject = user.Username
	claims.Issuer = s.opt.Issuer
	claims.Audience = jwt.ClaimStrings{s.opt.Audience}
	claims.IssuedAt = jwt.NewNumericDate(now)
	claims.ExpiresAt = jwt.NewNumericDate(now.Add(s.opt.AccessTTL))
	return &Tokens{AccessToken: access, RefreshToken: refresh, ExpiresIn: int64(s.opt.AccessTTL.Seconds())}, claims, nil
}

// Refresh atomically rotates the refresh grant and issues a new pair.
// Replay of an already-used token revokes the entire session family (S-04).
func (s *Service) Refresh(ctx context.Context, rawRefresh, ip, userAgent string) (*Tokens, *AccessClaims, error) {
	var rc RefreshClaims
	if err := s.keys.Parse(rawRefresh, &rc); err != nil {
		s.met.RefreshTotal.WithLabelValues("invalid").Inc()
		return nil, nil, ErrInvalidToken("")
	}
	if rc.TokenUse != UseRefresh {
		s.met.RefreshTotal.WithLabelValues("invalid").Inc()
		return nil, nil, ErrInvalidToken("")
	}

	retry, ok, err := s.lim.AllowRefresh(ctx, rc.Subject)
	if err != nil {
		s.met.RefreshTotal.WithLabelValues("error").Inc()
		return nil, nil, ErrUnavailable()
	}
	if !ok {
		s.met.RefreshTotal.WithLabelValues("rate_limited").Inc()
		s.audit.RateLimited(ctx, rc.Subject, ip, "refresh")
		return nil, nil, ErrRateLimited(retry)
	}

	// Load the current session record for original metadata (created_at,
	// DN, profile). The CAS rotation below is the actual source of truth.
	fam, err := s.sess.GetFamily(ctx, rc.FamilyID)
	if err != nil {
		// Unknown/expired family -> generic invalid token (S-08 style).
		s.met.RefreshTotal.WithLabelValues("invalid").Inc()
		return nil, nil, ErrInvalidToken("")
	}

	// Re-read roles from the directory so role revocation propagates at the
	// next refresh, not just at the next login (S-12). Fail-closed: if the
	// directory is unavailable we refuse to issue new tokens (S-07).
	roles, name, email := fam.Roles, fam.DisplayName, fam.Email
	if fam.DN != "" {
		user, err := s.dir.UserByDN(fam.DN)
		if err != nil {
			if err == ldap.ErrInvalidCredentials {
				// The account disappeared/disabled in AD: kill the session.
				_ = s.sess.RevokeFamily(ctx, rc.FamilyID)
				s.met.RefreshTotal.WithLabelValues("invalid").Inc()
				return nil, nil, ErrInvalidToken("")
			}
			s.met.RefreshTotal.WithLabelValues("error").Inc()
			return nil, nil, ErrUnavailable()
		}
		if user.Username != rc.Subject {
			// DN now points at a different identity — integrity violation.
			_ = s.sess.RevokeFamily(ctx, rc.FamilyID)
			s.met.RefreshTotal.WithLabelValues("invalid").Inc()
			return nil, nil, ErrInvalidToken("")
		}
		roles, name, email = user.Roles, user.DisplayName, user.Email
	}

	now := s.now()
	newJTI := newID()
	jtiA := newID()
	err = s.sess.Rotate(ctx, rc.FamilyID, rc.ID, &session.Session{
		FamilyID:    rc.FamilyID,
		JTI:         newJTI,
		Username:    rc.Subject,
		UserAgent:   userAgent,
		IP:          ip,
		CreatedAt:   fam.CreatedAt,
		Roles:       roles,
		DN:          fam.DN,
		DisplayName: name,
		Email:       email,
	})
	switch {
	case err == session.ErrReplay:
		// S-04: the grant was already used — treat as compromise. The store
		// has revoked the whole family; the client gets a plain 401.
		s.met.RefreshTotal.WithLabelValues("replay").Inc()
		s.audit.Refresh(ctx, rc.Subject, ip, userAgent, "replay", rc.ID)
		return nil, nil, ErrInvalidToken("")
	case err != nil:
		s.met.RefreshTotal.WithLabelValues("error").Inc()
		return nil, nil, ErrUnavailable()
	}

	access, err := s.signAccess(rc.Subject, "", "", roles, rc.FamilyID, jtiA, now, s.opt.AccessTTL)
	if err != nil {
		return nil, nil, ErrUnavailable()
	}
	refresh, err := s.signRefresh(rc.Subject, rc.FamilyID, newJTI, now, s.opt.RefreshTTL)
	if err != nil {
		return nil, nil, ErrUnavailable()
	}

	s.met.RefreshTotal.WithLabelValues("success").Inc()
	s.audit.Refresh(ctx, rc.Subject, ip, userAgent, "success", newJTI)

	claims := &AccessClaims{
		TokenUse:    UseAccess,
		Roles:       roles,
		FamilyID:    rc.FamilyID,
		DisplayName: name,
		Email:       email,
	}
	claims.Subject = rc.Subject
	claims.Issuer = s.opt.Issuer
	claims.Audience = jwt.ClaimStrings{s.opt.Audience}
	claims.IssuedAt = jwt.NewNumericDate(now)
	claims.ExpiresAt = jwt.NewNumericDate(now.Add(s.opt.AccessTTL))
	return &Tokens{AccessToken: access, RefreshToken: refresh, ExpiresIn: int64(s.opt.AccessTTL.Seconds())}, claims, nil
}

// Logout revokes the session family referenced by the access token.
func (s *Service) Logout(ctx context.Context, claims *AccessClaims, ip, userAgent string) error {
	err := s.sess.RevokeFamily(ctx, claims.FamilyID)
	result := "success"
	if err != nil {
		result = "error"
	}
	s.audit.Logout(ctx, claims.Subject, ip, userAgent, result, claims.FamilyID)
	return err
}

// Me returns the user's own profile from the local DB cache (F-04: no
// LDAP call). A soft-deleted profile yields a plain 401 so the client
// re-authenticates (which re-activates the profile).
func (s *Service) Me(ctx context.Context, claims *AccessClaims) (*userstore.User, error) {
	u, err := s.users.GetActiveByUsername(ctx, claims.Subject)
	if err == userstore.ErrNotFound {
		return nil, ErrInvalidToken("")
	}
	if err != nil {
		return nil, ErrUnavailable()
	}
	return u, nil
}

// Users lists cached profiles with filtering (admin).
func (s *Service) Users(ctx context.Context, f userstore.ListFilter) ([]userstore.User, string, error) {
	users, next, err := s.users.List(ctx, f)
	if err != nil {
		return nil, "", ErrUnavailable()
	}
	return users, next, nil
}

// UserByID returns one cached profile (admin).
func (s *Service) UserByID(ctx context.Context, id uuid.UUID) (*userstore.User, error) {
	u, err := s.users.GetByID(ctx, id)
	if err == userstore.ErrNotFound {
		return nil, ErrNotFound("user not found")
	}
	if err != nil {
		return nil, ErrUnavailable()
	}
	return u, nil
}

// DeleteUser soft-deletes a profile and revokes all its sessions (admin).
// AD remains the source of truth: the next login re-activates the profile.
func (s *Service) DeleteUser(ctx context.Context, actor string, id uuid.UUID) error {
	u, err := s.users.GetByID(ctx, id)
	if err == userstore.ErrNotFound {
		return ErrNotFound("user not found")
	}
	if err != nil {
		return ErrUnavailable()
	}
	if err := s.users.SoftDelete(ctx, id); err != nil {
		return ErrUnavailable()
	}
	if err := s.sess.RevokeUserSessions(ctx, u.Username); err != nil {
		return ErrUnavailable()
	}
	s.audit.SessionRevoked(ctx, actor, u.Username, "profile_deleted", "success")
	return nil
}

// RevokeSession revokes a family by id (admin action, F-06).
func (s *Service) RevokeSession(ctx context.Context, actor string, familyID string) error {
	info, err := s.sess.GetFamily(ctx, familyID)
	target := ""
	if err == nil && info != nil {
		target = info.Username
	}
	err = s.sess.RevokeFamily(ctx, familyID)
	result := "success"
	if err != nil && err != session.ErrSessionNotFound {
		result = "error"
	} else if err == session.ErrSessionNotFound {
		result = "not_found"
	}
	s.audit.SessionRevoked(ctx, actor, target, familyID, result)
	return err
}

// Ready verifies all backend dependencies (LDAP, Redis, PostgreSQL) —
// fail-closed: any failure makes /ready and /auth/* return 503 (S-07).
func (s *Service) Ready(ctx context.Context) error {
	if err := s.dir.Ping(); err != nil {
		return fmt.Errorf("ldap: %w", err)
	}
	if err := s.sess.Ping(ctx); err != nil {
		return fmt.Errorf("redis: %w", err)
	}
	if err := s.users.Ping(ctx); err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	return nil
}

// Sessions lists sessions with optional username filter (F-05).
func (s *Service) Sessions(ctx context.Context, username string, limit int, cursor string) ([]session.SessionInfo, string, error) {
	if username != "" {
		return s.sess.ListByUser(ctx, username, limit, cursor)
	}
	return s.sess.ListAll(ctx, limit, cursor)
}

// --- signing helpers ------------------------------------------------------

func (s *Service) signAccess(sub, name, email string, roles []string, familyID, jti string, now time.Time, ttl time.Duration) (string, error) {
	c := AccessClaims{
		TokenUse:    UseAccess,
		Roles:       roles,
		FamilyID:    familyID,
		DisplayName: name,
		Email:       email,
	}
	c.Subject = sub
	c.Issuer = s.opt.Issuer
	c.Audience = jwt.ClaimStrings{s.opt.Audience}
	c.IssuedAt = jwt.NewNumericDate(now)
	c.ExpiresAt = jwt.NewNumericDate(now.Add(ttl))
	c.NotBefore = jwt.NewNumericDate(now)
	c.ID = jti
	return s.keys.Sign(&c)
}

func (s *Service) signRefresh(sub, familyID, jti string, now time.Time, ttl time.Duration) (string, error) {
	c := RefreshClaims{
		TokenUse: UseRefresh,
		FamilyID: familyID,
	}
	c.Subject = sub
	c.Issuer = s.opt.Issuer
	c.Audience = jwt.ClaimStrings{s.opt.Audience}
	c.IssuedAt = jwt.NewNumericDate(now)
	c.ExpiresAt = jwt.NewNumericDate(now.Add(ttl))
	c.NotBefore = jwt.NewNumericDate(now)
	c.ID = jti
	return s.keys.Sign(&c)
}
