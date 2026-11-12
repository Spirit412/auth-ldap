package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/redis/go-redis/v9"

	"aps.local/apps/api/internal/audit"
	"aps.local/apps/api/internal/jwks"
	"aps.local/apps/api/internal/ldap"
	"aps.local/apps/api/internal/metrics"
	"aps.local/apps/api/internal/session"
	"aps.local/apps/api/internal/userstore"
)

// --- fakes ---------------------------------------------------------------

type fakeDirectory struct {
	users     map[string]*ldap.User
	authErr   error
	byDN      map[string]*ldap.User
	authCalls int
}

func (f *fakeDirectory) Authenticate(username, password string) (*ldap.User, error) {
	f.authCalls++
	if f.authErr != nil {
		return nil, f.authErr
	}
	if u, ok := f.users[username]; ok && password == "right-password" {
		return u, nil
	}
	return nil, ldap.ErrInvalidCredentials
}

func (f *fakeDirectory) UserByDN(dn string) (*ldap.User, error) {
	if u, ok := f.byDN[dn]; ok {
		return u, nil
	}
	return nil, ldap.ErrInvalidCredentials
}

func (f *fakeDirectory) Ping() error { return nil }

func (f *fakeDirectory) SelfBindMode() bool { return false }

type fakeLimiter struct {
	denyLogin   bool
	denyRefresh bool
	err         error
	loginCalls  int
}

func (f *fakeLimiter) AllowLogin(ctx context.Context, ip, username string) (time.Duration, bool, error) {
	f.loginCalls++
	if f.err != nil {
		return 0, false, f.err
	}
	if f.denyLogin {
		return 45 * time.Second, false, nil
	}
	return 0, true, nil
}

func (f *fakeLimiter) AllowRefresh(ctx context.Context, userID string) (time.Duration, bool, error) {
	if f.err != nil {
		return 0, false, f.err
	}
	if f.denyRefresh {
		return 10 * time.Second, false, nil
	}
	return 0, true, nil
}

type fakeUserStore struct {
	upserted []string
	profiles map[string]*userstore.User
	deleted  bool
}

func (f *fakeUserStore) UpsertFromLogin(ctx context.Context, u *ldap.User) (*userstore.User, error) {
	f.upserted = append(f.upserted, u.Username)
	return &userstore.User{Username: u.Username}, nil
}
func (f *fakeUserStore) GetActiveByUsername(ctx context.Context, username string) (*userstore.User, error) {
	if u, ok := f.profiles[username]; ok {
		return u, nil
	}
	return nil, userstore.ErrNotFound
}
func (f *fakeUserStore) GetByID(ctx context.Context, id uuid.UUID) (*userstore.User, error) {
	return nil, userstore.ErrNotFound
}
func (f *fakeUserStore) List(ctx context.Context, f2 userstore.ListFilter) ([]userstore.User, string, error) {
	return nil, "", nil
}
func (f *fakeUserStore) SoftDelete(ctx context.Context, id uuid.UUID) error {
	f.deleted = true
	return nil
}
func (f *fakeUserStore) Ping(ctx context.Context) error { return nil }

func newTestKeystore() (*jwks.Keystore, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	return jwks.NewInMemory(key, "test-kid", "aps", "aps-clients")
}

func nopMetrics() *metrics.Metrics { return metrics.New(prometheus.NewRegistry()) }
func nopAudit() *audit.Logger      { return audit.New() }

// --- harness --------------------------------------------------------------

func newTestService(t *testing.T) (*Service, *fakeDirectory, *fakeLimiter, *fakeUserStore, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })

	ks, err := newTestKeystore()
	if err != nil {
		t.Fatal(err)
	}
	dir := &fakeDirectory{
		users: map[string]*ldap.User{
			"alice": {
				DN:          "CN=alice,OU=users,DC=mca,DC=local",
				Username:    "alice",
				DisplayName: "Alice A",
				Email:       "alice@mca.local",
				Roles:       []string{"admin"},
			},
			"bob": {
				DN:       "CN=bob,OU=users,DC=mca,DC=local",
				Username: "bob",
				Roles:    []string{},
			},
		},
		byDN: map[string]*ldap.User{
			"CN=alice,OU=users,DC=mca,DC=local": {
				DN:          "CN=alice,OU=users,DC=mca,DC=local",
				Username:    "alice",
				Roles:       []string{"admin"},
				DisplayName: "Alice A",
				Email:       "alice@mca.local",
			},
		},
	}
	store := session.New(rdb, "t:", 168*time.Hour)
	users := &fakeUserStore{profiles: map[string]*userstore.User{
		"alice": {Username: "alice", DisplayName: "Alice A", Email: "alice@mca.local", Roles: []string{"admin"}},
	}}
	lim := &fakeLimiter{}
	svc := NewService(ks, dir, store, users, lim, nopAudit(), nopMetrics(), Options{
		Issuer: "aps", Audience: "aps-clients",
		AccessTTL: 15 * time.Minute, RefreshTTL: 168 * time.Hour,
	})
	return svc, dir, lim, users, mr
}

func TestLoginIssuesTokenPair(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	ctx := context.Background()

	tokens, claims, err := svc.Login(ctx, "alice", "right-password", "1.2.3.4", "ua/1")
	if err != nil {
		t.Fatal(err)
	}
	if tokens.AccessToken == "" || tokens.RefreshToken == "" {
		t.Fatal("tokens must be non-empty")
	}
	if tokens.ExpiresIn != int64((15 * time.Minute).Seconds()) {
		t.Fatalf("expires_in = %d", tokens.ExpiresIn)
	}
	if claims.Subject != "alice" || claims.TokenUse != UseAccess {
		t.Fatalf("access claims wrong: %+v", claims)
	}
	if len(claims.Roles) != 1 || claims.Roles[0] != "admin" {
		t.Fatalf("roles wrong: %v", claims.Roles)
	}
	if claims.FamilyID == "" || claims.ID == "" {
		t.Fatal("fid/jti must be present")
	}
	if claims.Issuer != "aps" {
		t.Fatalf("iss = %q", claims.Issuer)
	}
}

func TestLoginInvalidCredentialsIsUniform401(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	ctx := context.Background()

	// wrong password for existing user
	_, _, err1 := svc.Login(ctx, "alice", "wrong", "1.2.3.4", "ua/1")
	// unknown user (S-08: identical error surface)
	_, _, err2 := svc.Login(ctx, "ghost", "whatever", "1.2.3.4", "ua/1")

	ae1, ok1 := err1.(*APIError)
	ae2, ok2 := err2.(*APIError)
	if !ok1 || !ok2 {
		t.Fatalf("both must be APIError: %v / %v", err1, err2)
	}
	if ae1.Status != 401 || ae2.Status != 401 {
		t.Fatalf("statuses: %d / %d", ae1.Status, ae2.Status)
	}
	if ae1.Detail != ae2.Detail {
		t.Fatalf("S-08 violated: details differ: %q vs %q", ae1.Detail, ae2.Detail)
	}
}

// S-13: when the limiter denies, AD must not be contacted at all.
func TestLoginRateLimitBlocksAD(t *testing.T) {
	ks, err := newTestKeystore()
	if err != nil {
		t.Fatal(err)
	}
	dir := &fakeDirectory{users: map[string]*ldap.User{}}
	lim := &fakeLimiter{denyLogin: true}
	svc := NewService(ks, dir, nil, nil, lim, nopAudit(), nopMetrics(), Options{Issuer: "aps", Audience: "aps-clients", AccessTTL: time.Minute, RefreshTTL: 24 * time.Hour})

	_, _, err = svc.Login(context.Background(), "alice", "x", "1.2.3.4", "ua")
	ae, ok := err.(*APIError)
	if !ok || ae.Status != 429 || ae.RetryAfter == 0 {
		t.Fatalf("want 429 with Retry-After, got %+v", err)
	}
	if dir.authCalls != 0 {
		t.Fatalf("S-13: AD must not be contacted, got %d calls", dir.authCalls)
	}
	if lim.loginCalls != 1 {
		t.Fatalf("limiter must be checked exactly once, got %d", lim.loginCalls)
	}
}

func TestLoginFailClosedOnLimiterError(t *testing.T) {
	ks, err := newTestKeystore()
	if err != nil {
		t.Fatal(err)
	}
	lim := &fakeLimiter{err: context.DeadlineExceeded}
	svc := NewService(ks, &fakeDirectory{}, nil, nil, lim, nopAudit(), nopMetrics(), Options{Issuer: "aps", Audience: "aps-clients", AccessTTL: time.Minute, RefreshTTL: 24 * time.Hour})
	_, _, err = svc.Login(context.Background(), "alice", "x", "1.2.3.4", "ua")
	if ae, ok := err.(*APIError); !ok || ae.Status != 503 {
		t.Fatalf("want 503 fail-closed, got %v", err)
	}
}

func TestRefreshRotateThenReplay(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	ctx := context.Background()

	tokens, _, err := svc.Login(ctx, "alice", "right-password", "1.2.3.4", "ua/1")
	if err != nil {
		t.Fatal(err)
	}

	// first refresh: ok, issues new pair
	t2, claims2, err := svc.Refresh(ctx, tokens.RefreshToken, "1.2.3.4", "ua/1")
	if err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if t2.AccessToken == "" || claims2.TokenUse != UseAccess {
		t.Fatal("refresh must issue a new access token")
	}

	// replay of the ORIGINAL refresh token: 401 and family revoked
	_, _, err = svc.Refresh(ctx, tokens.RefreshToken, "1.2.3.4", "ua/1")
	if ae, ok := err.(*APIError); !ok || ae.Status != 401 {
		t.Fatalf("replay must be 401, got %v", err)
	}

	// even the NEWEST refresh token is dead now (whole family revoked)
	_, _, err = svc.Refresh(ctx, t2.RefreshToken, "1.2.3.4", "ua/1")
	if ae, ok := err.(*APIError); !ok || ae.Status != 401 {
		t.Fatalf("family must be fully revoked, got %v", err)
	}
}

func TestRefreshRejectsAccessToken(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	ctx := context.Background()
	tokens, _, err := svc.Login(ctx, "alice", "right-password", "1.2.3.4", "ua/1")
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = svc.Refresh(ctx, tokens.AccessToken, "1.2.3.4", "ua/1")
	if ae, ok := err.(*APIError); !ok || ae.Status != 401 {
		t.Fatalf("access token must not work as refresh, got %v", err)
	}
}

// S-12: roles are re-read from AD on refresh; a demoted admin loses the role.
func TestRefreshReReadsRoles(t *testing.T) {
	svc, dir, _, _, _ := newTestService(t)
	ctx := context.Background()

	tokens, claims, err := svc.Login(ctx, "alice", "right-password", "1.2.3.4", "ua/1")
	if err != nil {
		t.Fatal(err)
	}
	if len(claims.Roles) != 1 {
		t.Fatal("alice must start as admin")
	}

	// demote: the directory no longer grants admin
	dir.byDN["CN=alice,OU=users,DC=mca,DC=local"].Roles = []string{}

	t2, claims2, err := svc.Refresh(ctx, tokens.RefreshToken, "1.2.3.4", "ua/1")
	if err != nil {
		t.Fatal(err)
	}
	_ = t2
	if len(claims2.Roles) != 0 {
		t.Fatalf("demoted admin must lose role on refresh, got %v", claims2.Roles)
	}
}

func TestLogoutRevokesFamily(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	ctx := context.Background()
	tokens, claims, err := svc.Login(ctx, "alice", "right-password", "1.2.3.4", "ua/1")
	if err != nil {
		t.Fatal(err)
	}
	if err := svc.Logout(ctx, claims, "1.2.3.4", "ua/1"); err != nil {
		t.Fatal(err)
	}
	_, _, err = svc.Refresh(ctx, tokens.RefreshToken, "1.2.3.4", "ua/1")
	if ae, ok := err.(*APIError); !ok || ae.Status != 401 {
		t.Fatalf("after logout refresh must be 401, got %v", err)
	}
}

func TestMeFromProfileCache(t *testing.T) {
	svc, _, _, _, _ := newTestService(t)
	ctx := context.Background()
	tokens, claims, err := svc.Login(ctx, "alice", "right-password", "1.2.3.4", "ua/1")
	if err != nil {
		t.Fatal(err)
	}
	_ = tokens
	u, err := svc.Me(ctx, claims)
	if err != nil {
		t.Fatal(err)
	}
	if u.Username != "alice" || u.DisplayName != "Alice A" {
		t.Fatalf("profile wrong: %+v", u)
	}
}
