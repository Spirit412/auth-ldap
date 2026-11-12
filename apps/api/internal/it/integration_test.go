//go:build integration

// Package it contains integration tests against real infrastructure:
// mock LDAP (glauth), Redis and PostgreSQL — the same shape as the dev
// docker-compose stack. Gated behind the `integration` build tag and the
// APS_IT_* environment variables so plain `go test` stays hermetic.
package it

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/redis/go-redis/v9"

	"aps.local/apps/api/internal/audit"
	"aps.local/apps/api/internal/auth"
	"aps.local/apps/api/internal/jwks"
	"aps.local/apps/api/internal/ldap"
	"aps.local/apps/api/internal/metrics"
	"aps.local/apps/api/internal/middleware"
	"aps.local/apps/api/internal/session"
	"aps.local/apps/api/internal/userstore"
)

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

type itFixture struct {
	svc *auth.Service
}

func newFixture(t *testing.T) *itFixture {
	t.Helper()
	ctx := context.Background()

	keys, err := jwks.Load(envOr("APS_IT_JWT_KEY", "../../deploy/keys/jwt-active.pem"),
		envOr("APS_IT_JWT_KID", "cc0ab106"), "", "aps", "aps-clients")
	if err != nil {
		t.Skipf("jwt key unavailable: %v", err)
	}

	dir, err := ldap.New(ldap.Settings{
		URL:          envOr("APS_IT_LDAP_URL", "ldaps://localhost:636"),
		InsecureTLS:  os.Getenv("APS_IT_LDAP_INSECURE") == "true",
		BindDN:       envOr("APS_IT_LDAP_BIND_DN", "cn=svc-bind,ou=svc,dc=mca,dc=local"),
		BindPassword: envOr("APS_IT_LDAP_BIND_PASSWORD", "svc-bind-secret"),
		BaseDN:       envOr("APS_IT_LDAP_BASE_DN", "dc=mca,dc=local"),
		UserAttr:     envOr("APS_IT_LDAP_USER_ATTR", "uid"),
		NameAttr:     envOr("APS_IT_LDAP_NAME_ATTR", "cn"),
		MailAttr:     envOr("APS_IT_LDAP_MAIL_ATTR", "mail"),
		AdminGroupDN: envOr("APS_IT_LDAP_ADMIN_GROUP_DN", "cn=aps-admins,ou=groups,dc=mca,dc=local"),
		PoolSize:     3,
		Timeout:      10 * time.Second,
		Retry:        2,
	})
	if err != nil {
		t.Skipf("ldap settings: %v", err)
	}
	if err := dir.Ping(); err != nil {
		t.Skipf("mock LDAP unreachable (start compose profile dev): %v", err)
	}

	rdb := redis.NewClient(&redis.Options{Addr: envOr("APS_IT_REDIS_ADDR", "localhost:6379"), Password: envOr("APS_IT_REDIS_PASSWORD", "")})
	if err := rdb.Ping(ctx).Err(); err != nil {
		t.Skipf("redis unreachable: %v", err)
	}
	pg, err := userstore.Open(fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		envOr("APS_IT_PG_USER", "aps"), envOr("APS_IT_PG_PASSWORD", "aps-test"),
		envOr("APS_IT_PG_HOST", "localhost"), envOr("APS_IT_PG_PORT", "5432"),
		envOr("APS_IT_PG_DB", "aps")), 5)
	if err != nil {
		t.Skipf("postgres unreachable: %v", err)
	}
	if err := userstore.MigrateUp(fmt.Sprintf("pgx5://%s:%s@%s:%s/%s?sslmode=disable",
		envOr("APS_IT_PG_USER", "aps"), envOr("APS_IT_PG_PASSWORD", "aps-test"),
		envOr("APS_IT_PG_HOST", "localhost"), envOr("APS_IT_PG_PORT", "5432"),
		envOr("APS_IT_PG_DB", "aps"))); err != nil {
		t.Skipf("migrate: %v", err)
	}

	store := session.New(rdb, "it:", 168*time.Hour)
	users := userstore.New(pg)
	lim := middleware.NewLimiter(rdb, "it:", 5, 15*time.Minute, 1*time.Minute)
	svc := auth.NewService(keys, dir, store, users, lim, audit.New(), metrics.New(nil), auth.Options{
		Issuer: "aps", Audience: "aps-clients",
		AccessTTL: 15 * time.Minute, RefreshTTL: 168 * time.Hour,
	})
	t.Cleanup(func() {
		_ = rdb.Close()
		if sqlDB, e := pg.DB(); e == nil {
			_ = sqlDB.Close()
		}
	})
	return &itFixture{svc: svc}
}

func TestIntegrationLoginFlows(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	t.Run("admin login succeeds and issues roles", func(t *testing.T) {
		tokens, claims, err := f.svc.Login(ctx, "alice", "alice_password", "127.0.0.1", "it-agent")
		if err != nil {
			t.Fatalf("alice login: %v", err)
		}
		if len(claims.Roles) != 1 || claims.Roles[0] != "admin" {
			t.Fatalf("alice must map to admin, got %v", claims.Roles)
		}
		if tokens.AccessToken == "" || tokens.RefreshToken == "" {
			t.Fatal("tokens missing")
		}
	})

	t.Run("unknown user matches wrong-password response shape", func(t *testing.T) {
		_, _, err1 := f.svc.Login(ctx, "alice", "wrong", "127.0.0.2", "it")
		_, _, err2 := f.svc.Login(ctx, "no-such-user", "whatever", "127.0.0.2", "it")
		e1, ok1 := err1.(*auth.APIError)
		e2, ok2 := err2.(*auth.APIError)
		if !ok1 || !ok2 || e1.Status != 401 || e2.Status != 401 || e1.Detail != e2.Detail {
			t.Fatalf("S-08: responses must be indistinguishable: %v / %v", err1, err2)
		}
	})

	t.Run("non-admin login has no roles", func(t *testing.T) {
		_, claims, err := f.svc.Login(ctx, "bob", "bob_password", "127.0.0.3", "it")
		if err != nil {
			t.Fatalf("bob login: %v", err)
		}
		if len(claims.Roles) != 0 {
			t.Fatalf("bob must have no roles, got %v", claims.Roles)
		}
	})

	t.Run("refresh rotation and replay revokes family", func(t *testing.T) {
		tokens, _, err := f.svc.Login(ctx, "alice", "alice_password", "127.0.0.4", "it")
		if err != nil {
			t.Fatal(err)
		}
		t2, _, err := f.svc.Refresh(ctx, tokens.RefreshToken, "127.0.0.4", "it")
		if err != nil {
			t.Fatalf("first refresh: %v", err)
		}
		// replay the original
		_, _, err = f.svc.Refresh(ctx, tokens.RefreshToken, "127.0.0.4", "it")
		if ae, ok := err.(*auth.APIError); !ok || ae.Status != 401 {
			t.Fatalf("replay must be 401, got %v", err)
		}
		// newest token is dead too
		_, _, err = f.svc.Refresh(ctx, t2.RefreshToken, "127.0.0.4", "it")
		if ae, ok := err.(*auth.APIError); !ok || ae.Status != 401 {
			t.Fatalf("family must be revoked, got %v", err)
		}
	})

	t.Run("rate limit is shared between two instances via redis", func(t *testing.T) {
		rdb := redis.NewClient(&redis.Options{Addr: envOr("APS_IT_REDIS_ADDR", "localhost:6379")})
		defer func() { _ = rdb.Close() }()
		l1 := middleware.NewLimiter(rdb, "itshared:", 3, time.Minute, time.Minute)
		l2 := middleware.NewLimiter(rdb, "itshared:", 3, time.Minute, time.Minute)
		key := fmt.Sprintf("user-%d", time.Now().UnixNano())

		for i := 0; i < 3; i++ {
			_, ok, err := l1.AllowRefresh(ctx, key)
			if err != nil || !ok {
				t.Fatalf("instance1 attempt %d denied: %v", i, err)
			}
		}
		// instance 2 sees the SAME counter (acceptance #10)
		_, ok, err := l2.AllowRefresh(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		if ok {
			t.Fatal("instance2 must observe the shared limit")
		}
	})
}

func TestIntegrationUserCache(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()

	tokens, claims, err := f.svc.Login(ctx, "alice", "alice_password", "127.0.0.5", "it")
	if err != nil {
		t.Fatal(err)
	}
	_ = tokens

	u, err := f.svc.Me(ctx, claims)
	if err != nil {
		t.Fatalf("me: %v", err)
	}
	if u.Username != "alice" || u.ID.String() == "" {
		t.Fatalf("profile from DB wrong: %+v", u)
	}
	if u.CreatedAt.IsZero() || u.UpdatedAt.IsZero() {
		t.Fatal("created_at/updated_at must be set")
	}
}
