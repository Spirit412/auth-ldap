// Package config loads APS configuration from environment variables.
//
// Security decisions (ТЗ F-12, S-11):
//   - The JWT private key is supplied as a FILE PATH (JWT_PRIVATE_KEY_FILE),
//     never as an inline value.
//   - LDAP scheme must be ldaps:// (or ldap:// only together with StartTLS).
//     Plain ldap:// without StartTLS is a configuration error (acceptance #2).
package config

import (
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/caarlos0/env/v11"
)

// Config is the full process configuration. Every field comes from env.
type Config struct {
	ListenAddr string `env:"LISTEN_ADDR" envDefault:":8080"`

	LogLevel  string `env:"LOG_LEVEL" envDefault:"info"`  // debug|info|warn|error
	LogFormat string `env:"LOG_FORMAT" envDefault:"json"` // json|console
	// Bootstrap admin: a LOCAL account for accessing the admin panel when
	// no AD admin group is configured yet. Password lives in .env (gitignored);
	// comparison is constant-time (subtle).
	AdminBootstrapUser     string `env:"APS_ADMIN_BOOTSTRAP_USER" envDefault:""`
	AdminBootstrapPassword string `env:"APS_ADMIN_PASSWORD" envDefault:""`

	// Admin state logs: daily files aps-YYYYMMDD.log, retention in days
	// (older files are deleted by a background sweep, default 3).
	LogFileDir       string `env:"LOG_FILE_DIR" envDefault:""` // empty = stderr only
	LogRetentionDays int    `env:"LOG_RETENTION_DAYS" envDefault:"3"`

	// --- LDAP (S-02: TLS mandatory) ---
	// LDAPURL must be ldaps://host:636. ldap:// is allowed only when
	// LDAPStartTLS=true (StartTLS upgrade before any bind).
	LDAPURL              string `env:"LDAP_URL"`
	LDAPStartTLS         bool   `env:"LDAP_STARTTLS" envDefault:"false"`
	LDAPCACertFile       string `env:"LDAP_CA_CERT_FILE"`                    // CA bundle for internal PKI
	LDAPTLSInsecure      bool   `env:"LDAP_TLS_INSECURE" envDefault:"false"` // TEST MODE ONLY (mock LDAP)
	LDAPBindDN           string `env:"LDAP_BIND_DN"`                         // read-only service account (S-03)
	LDAPBindPassword     string `env:"LDAP_BIND_PASSWORD"`                   // or _FILE variant below
	LDAPBindPasswordFile string `env:"LDAP_BIND_PASSWORD_FILE"`              // secret-file alternative
	LDAPBaseDN           string `env:"LDAP_BASE_DN"`
	// LDAPObjectClass: AD serves the full class chain (person matches);
	// simple mock servers (glauth) only serve leaf classes — set inetOrgPerson.
	LDAPObjectClass string `env:"LDAP_OBJECT_CLASS" envDefault:"person"`
	// LDAPUserAttr is the login attribute. Default sAMAccountName (AD);
	// mock glauth uses uid. The filter structure itself stays constant (S-01).
	LDAPUserAttr string `env:"LDAP_USER_ATTR" envDefault:"sAMAccountName"`
	LDAPNameAttr string `env:"LDAP_NAME_ATTR" envDefault:"displayName"`
	LDAPMailAttr string `env:"LDAP_MAIL_ATTR" envDefault:"mail"`
	// LDAPUPNSuffix enables UPN logins: "user@<suffix>" is searched by
	// userPrincipalName; other domains and "DOMAIN\user" are normalised to
	// the short name. Empty disables UPN handling.
	LDAPUPNSuffix string `env:"LDAP_UPN_SUFFIX" envDefault:""`
	// LDAPNetBIOSDomain: self-bind mode builds "DOMAIN\user" bind names
	// when the login is a bare sAMAccountName.
	LDAPNetBIOSDomain string        `env:"LDAP_NETBIOS_DOMAIN" envDefault:""`
	LDAPAdminGroupDN  string        `env:"LDAP_ADMIN_GROUP_DN"` // S-12: maps to roles=["admin"]
	LDAPPoolSize      int           `env:"LDAP_POOL_SIZE" envDefault:"5"`
	LDAPTimeout       time.Duration `env:"LDAP_TIMEOUT" envDefault:"10s"`
	LDAPRetry         int           `env:"LDAP_RETRY" envDefault:"3"` // transient dial retries

	// --- Redis (shared instance: every key gets the aps: prefix) ---
	RedisAddr      string `env:"REDIS_ADDR" envDefault:"localhost:6379"`
	RedisPassword  string `env:"REDIS_PASSWORD"`
	RedisDB        int    `env:"REDIS_DB" envDefault:"0"`
	RedisTLS       bool   `env:"REDIS_TLS" envDefault:"false"`
	RedisKeyPrefix string `env:"REDIS_KEY_PREFIX" envDefault:"aps:"`

	// --- PostgreSQL (user profile cache; GORM + golang-migrate) ---
	PGHost     string `env:"PG_HOST" envDefault:"localhost"`
	PGPort     int    `env:"PG_PORT" envDefault:"5432"`
	PGUser     string `env:"PG_USER" envDefault:"aps"`
	PGPassword string `env:"PG_PASSWORD"`
	PGDatabase string `env:"PG_DATABASE" envDefault:"aps"`
	PGSSLMode  string `env:"PG_SSLMODE" envDefault:"prefer"`
	PGPoolMax  int    `env:"PG_POOL_MAX" envDefault:"10"`
	DBMigrate  bool   `env:"DB_MIGRATE" envDefault:"true"` // run migrations at startup

	// --- JWT keys (S-05, S-11, S-12) ---
	JWTPrivateKeyFile string `env:"JWT_PRIVATE_KEY_FILE" envDefault:""` // required (path!)
	JWTKeyID          string `env:"JWT_KEY_ID" envDefault:""`           // required kid
	JWTPrevKeysDir    string `env:"JWT_PREV_KEYS_DIR"`                  // previous public keys <kid>.pem
	JWTIssuer         string `env:"JWT_ISSUER" envDefault:"aps"`
	JWTAudience       string `env:"JWT_AUDIENCE" envDefault:"aps-clients"`

	AccessTokenTTL  time.Duration `env:"ACCESS_TOKEN_TTL" envDefault:"15m"`   // S-05: max 15m
	RefreshTokenTTL time.Duration `env:"REFRESH_TOKEN_TTL" envDefault:"168h"` // S-05: 7..30d

	// --- HTTP surface ---
	TrustedProxies []string `env:"TRUSTED_PROXIES" envSeparator:","` // CIDRs for X-Forwarded-For
	DocsEnabled    bool     `env:"DOCS_ENABLED" envDefault:"true"`   // /docs + /openapi.json (F-13)
	CookieSecure   bool     `env:"COOKIE_SECURE" envDefault:"true"`  // aps_refresh Secure flag
	CookieDomain   string   `env:"COOKIE_DOMAIN"`                    // empty = host-only

	// --- Rate limiting (S-06, redis_rate/GCRA in Redis) ---
	LoginRateLimit    int           `env:"LOGIN_RATE_LIMIT" envDefault:"5"`
	LoginRateWindow   time.Duration `env:"LOGIN_RATE_WINDOW" envDefault:"15m"`
	RefreshRateLimit  int           `env:"REFRESH_RATE_LIMIT" envDefault:"10"`
	RefreshRateWindow time.Duration `env:"REFRESH_RATE_WINDOW" envDefault:"1m"`
}

// Load parses env into Config and validates security-critical invariants.
func Load() (*Config, error) {
	cfg := &Config{}
	if err := env.Parse(cfg); err != nil {
		return nil, fmt.Errorf("parse env: %w", err)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// Validate enforces fail-closed configuration rules.
func (c *Config) Validate() error {
	if c.ListenAddr == "" {
		return fmt.Errorf("LISTEN_ADDR is required")
	}

	// S-02: only LDAPS, or plain LDAP together with an explicit StartTLS opt-in.
	scheme := ""
	if i := strings.Index(c.LDAPURL, "://"); i > 0 {
		scheme = strings.ToLower(c.LDAPURL[:i])
	}
	switch {
	case scheme == "ldaps":
		// ok
	case scheme == "ldap" && c.LDAPStartTLS:
		// ok: upgraded to TLS before any operation
	default:
		return fmt.Errorf("LDAP_URL must be ldaps://host:636 (ldap:// is allowed only with LDAP_STARTTLS=true), got %q", c.LDAPURL)
	}
	if c.LDAPURL == "" {
		return fmt.Errorf("LDAP_URL is required")
	}
	// BaseDN is always required; BIND_DN/PASSWORD may both be empty ->
	// self-bind mode (AD binds AS the user, no service account needed).
	if c.LDAPBaseDN == "" {
		return fmt.Errorf("LDAP_BASE_DN is required")
	}
	if c.LDAPPoolSize < 1 {
		c.LDAPPoolSize = 1
	}
	if c.LDAPTimeout <= 0 {
		return fmt.Errorf("LDAP_TIMEOUT must be positive")
	}

	if c.RedisAddr == "" {
		return fmt.Errorf("REDIS_ADDR is required")
	}

	if c.PGHost == "" {
		return fmt.Errorf("PG_HOST is required")
	}
	if c.PGUser == "" || c.PGDatabase == "" {
		return fmt.Errorf("PG_USER and PG_DATABASE are required")
	}

	// S-11: private key must come from a file path; kid is mandatory so that
	// JWKS consumers can select the right key.
	if c.JWTPrivateKeyFile == "" {
		return fmt.Errorf("JWT_PRIVATE_KEY_FILE is required (path to PEM file)")
	}
	if c.JWTKeyID == "" {
		return fmt.Errorf("JWT_KEY_ID is required")
	}

	// S-05: access tokens are short-lived; refresh window 7..30 days.
	if c.AccessTokenTTL <= 0 || c.AccessTokenTTL > 15*time.Minute {
		return fmt.Errorf("ACCESS_TOKEN_TTL must be in (0; 15m]")
	}
	if c.RefreshTokenTTL < 7*24*time.Hour || c.RefreshTokenTTL > 30*24*time.Hour {
		return fmt.Errorf("REFRESH_TOKEN_TTL must be between 168h (7d) and 720h (30d)")
	}

	// S-06 defaults match the ТЗ; only allow tightening, not disabling.
	if c.LoginRateLimit < 1 || c.RefreshRateLimit < 1 {
		return fmt.Errorf("rate limits must be >= 1")
	}
	return nil
}

// postgresURL builds the postgres:// DSN for GORM (URL-escaped).
func (c *Config) postgresURL(scheme string) string {
	u := url.URL{
		Scheme: scheme,
		User:   url.UserPassword(c.PGUser, c.PGPassword),
		Host:   fmt.Sprintf("%s:%d", c.PGHost, c.PGPort),
		Path:   c.PGDatabase,
	}
	q := url.Values{}
	q.Set("sslmode", c.PGSSLMode)
	u.RawQuery = q.Encode()
	return u.String()
}

// GORMDSN returns the postgres:// DSN used by gorm.Open.
func (c *Config) GORMDSN() string { return c.postgresURL("postgres") }

// MigrateDSN returns the pgx5:// DSN used by golang-migrate.
func (c *Config) MigrateDSN() string { return c.postgresURL("pgx5") }

// BindPassword resolves the LDAP service password, honouring the _FILE
// variant used by Docker/K8s secret mounts.
func (c *Config) BindPassword() (string, error) {
	if c.LDAPBindPasswordFile != "" {
		b, err := os.ReadFile(c.LDAPBindPasswordFile)
		if err != nil {
			return "", fmt.Errorf("read LDAP_BIND_PASSWORD_FILE: %w", err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	return c.LDAPBindPassword, nil
}
