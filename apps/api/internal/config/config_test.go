package config

import (
	"strings"
	"testing"
	"time"
)

// validBase returns an env map that passes validation; individual tests
// override fields to trigger specific failures.
func validBase() map[string]string {
	return map[string]string{
		"LDAP_URL":             "ldaps://ad.mca.local:636",
		"LDAP_BIND_DN":         "CN=svc-aps,OU=service,DC=mca,DC=local",
		"LDAP_BIND_PASSWORD":   "secret",
		"LDAP_BASE_DN":         "DC=mca,DC=local",
		"JWT_PRIVATE_KEY_FILE": "/keys/jwt.pem",
		"JWT_KEY_ID":           "kid-1",
		"REDIS_ADDR":           "localhost:6379",
		"PG_HOST":              "postgres",
		"PG_USER":              "aps",
		"PG_DATABASE":          "aps",
	}
}

func loadFrom(t *testing.T, env map[string]string) (*Config, error) {
	t.Helper()
	// pin durations explicitly; individual tests override
	t.Setenv("ACCESS_TOKEN_TTL", "15m")
	t.Setenv("REFRESH_TOKEN_TTL", "168h")
	for k, v := range env {
		t.Setenv(k, v)
	}
	return Load()
}

// Acceptance #2: plain ldap:// must be a configuration error.
func TestValidateRejectsPlainLDAP(t *testing.T) {
	env := validBase()
	env["LDAP_URL"] = "ldap://ad.mca.local:389"
	if _, err := loadFrom(t, env); err == nil || !strings.Contains(err.Error(), "ldaps") {
		t.Fatalf("ldap:// must fail config validation, got %v", err)
	}

	// ...unless StartTLS is explicitly enabled (S-02 allows it).
	env["LDAP_STARTTLS"] = "true"
	if _, err := loadFrom(t, env); err != nil {
		t.Fatalf("ldap:// + StartTLS must be accepted, got %v", err)
	}
}

func TestValidateRequiresKeyFile(t *testing.T) {
	env := validBase()
	delete(env, "JWT_PRIVATE_KEY_FILE")
	if _, err := loadFrom(t, env); err == nil {
		t.Fatal("missing JWT_PRIVATE_KEY_FILE must fail")
	}
}

func TestValidateRequiresKid(t *testing.T) {
	env := validBase()
	delete(env, "JWT_KEY_ID")
	if _, err := loadFrom(t, env); err == nil {
		t.Fatal("missing JWT_KEY_ID must fail")
	}
}

func TestValidateTTLBounds(t *testing.T) {
	env := validBase()
	env["ACCESS_TOKEN_TTL"] = "1h" // longer than the 15m maximum
	if _, err := loadFrom(t, env); err == nil {
		t.Fatal("access TTL above 15m must fail")
	}
	env = validBase()
	env["REFRESH_TOKEN_TTL"] = "1h" // below the 7d minimum
	if _, err := loadFrom(t, env); err == nil {
		t.Fatal("refresh TTL below 7d must fail")
	}
}

func TestDefaults(t *testing.T) {
	cfg, err := loadFrom(t, validBase())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.AccessTokenTTL != 15*time.Minute {
		t.Fatalf("access ttl = %v", cfg.AccessTokenTTL)
	}
	if cfg.RefreshTokenTTL != 168*time.Hour {
		t.Fatalf("refresh ttl = %v", cfg.RefreshTokenTTL)
	}
	if cfg.RedisKeyPrefix != "aps:" {
		t.Fatalf("key prefix = %v", cfg.RedisKeyPrefix)
	}
	if !cfg.DocsEnabled || !cfg.CookieSecure {
		t.Fatal("docs and secure cookie must default to enabled")
	}
	if cfg.LoginRateLimit != 5 || cfg.RefreshRateLimit != 10 {
		t.Fatal("rate limit defaults must match the ТЗ (5/15min, 10/min)")
	}
}

func TestGORMDSN(t *testing.T) {
	cfg, err := loadFrom(t, validBase())
	if err != nil {
		t.Fatal(err)
	}
	dsn := cfg.GORMDSN()
	if !strings.Contains(dsn, "@postgres:5432/aps?sslmode=prefer") {
		t.Fatalf("unexpected dsn: %s", dsn)
	}
	if !strings.HasPrefix(cfg.MigrateDSN(), "pgx5://") {
		t.Fatalf("migrate dsn must use pgx5 scheme: %s", cfg.MigrateDSN())
	}
}
