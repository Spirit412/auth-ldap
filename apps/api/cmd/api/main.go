// APS entrypoint: builds all dependencies and runs the HTTP server with
// graceful shutdown. Thin on purpose — all logic lives in internal/.
package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/redis/go-redis/v9"
	"github.com/rs/zerolog"

	"aps.local/apps/api/internal/audit"
	"aps.local/apps/api/internal/auth"
	"aps.local/apps/api/internal/config"
	"aps.local/apps/api/internal/httpapi"
	"aps.local/apps/api/internal/jwks"
	"aps.local/apps/api/internal/ldap"
	"aps.local/apps/api/internal/metrics"
	"aps.local/apps/api/internal/middleware"
	"aps.local/apps/api/internal/session"
	"aps.local/apps/api/internal/userstore"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	logger := newLogger(cfg)
	log := logger.With().Str("component", "main").Logger()
	log.Info().Str("version", version).Msg("starting APS")

	// --- JWT keystore (S-11: private key from file, kid required) --------
	keys, err := jwks.Load(cfg.JWTPrivateKeyFile, cfg.JWTKeyID, cfg.JWTPrevKeysDir, cfg.JWTIssuer, cfg.JWTAudience)
	if err != nil {
		return fmt.Errorf("jwks keystore: %w", err)
	}

	// --- LDAP client (S-02: LDAPS only) ----------------------------------
	bindPassword, err := cfg.BindPassword()
	if err != nil {
		return err
	}
	dir, err := ldap.New(ldap.Settings{
		URL:          cfg.LDAPURL,
		StartTLS:     cfg.LDAPStartTLS,
		CAFile:       cfg.LDAPCACertFile,
		InsecureTLS:  cfg.LDAPTLSInsecure,
		BindDN:       cfg.LDAPBindDN,
		BindPassword: bindPassword,
		BaseDN:       cfg.LDAPBaseDN,
		UserAttr:     cfg.LDAPUserAttr,
		NameAttr:     cfg.LDAPNameAttr,
		MailAttr:     cfg.LDAPMailAttr,
		AdminGroupDN: cfg.LDAPAdminGroupDN,
		UPNSuffix:    cfg.LDAPUPNSuffix,
		PoolSize:     cfg.LDAPPoolSize,
		Timeout:      cfg.LDAPTimeout,
		Retry:        cfg.LDAPRetry,
	})
	if err != nil {
		return fmt.Errorf("ldap client: %w", err)
	}
	defer dir.Close()

	// --- Redis (shared instance, prefixed keys) ---------------------------
	var redisTLS *tls.Config
	if cfg.RedisTLS {
		redisTLS = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	rdb := redis.NewClient(&redis.Options{
		Addr:      cfg.RedisAddr,
		Password:  cfg.RedisPassword,
		DB:        cfg.RedisDB,
		TLSConfig: redisTLS,
	})
	defer func() { _ = rdb.Close() }()
	sessions := session.New(rdb, cfg.RedisKeyPrefix, cfg.RefreshTokenTTL)
	limiter := middleware.NewLimiter(rdb, cfg.RedisKeyPrefix, cfg.LoginRateLimit, cfg.LoginRateWindow, cfg.RefreshRateWindow)

	// --- PostgreSQL profile cache (GORM + golang-migrate) -----------------
	if cfg.DBMigrate {
		if err := userstore.MigrateUp(cfg.MigrateDSN()); err != nil {
			return fmt.Errorf("db migrate: %w", err)
		}
		log.Info().Msg("database migrations applied")
	}
	gdb, err := userstore.Open(cfg.GORMDSN(), cfg.PGPoolMax)
	if err != nil {
		return fmt.Errorf("postgres: %w", err)
	}
	users := userstore.New(gdb)
	defer users.Close()

	// --- Service wiring ----------------------------------------------------
	met := metrics.New(nil)
	aud := audit.New()
	svc := auth.NewService(keys, dir, sessions, users, limiter, aud, met, auth.Options{
		Issuer:       cfg.JWTIssuer,
		Audience:     cfg.JWTAudience,
		AdminGroupDN: cfg.LDAPAdminGroupDN,
		AccessTTL:    cfg.AccessTokenTTL,
		RefreshTTL:   cfg.RefreshTokenTTL,
	})

	realIP, err := middleware.NewRealIP(cfg.TrustedProxies)
	if err != nil {
		return fmt.Errorf("trusted proxies: %w", err)
	}

	handler, _ := httpapi.NewRouter(httpapi.Deps{
		Svc:     svc,
		Keys:    keys,
		Logger:  logger,
		Met:     met,
		RealIP:  realIP,
		Cookie:  httpapi.CookieCfg{Secure: cfg.CookieSecure, Domain: cfg.CookieDomain, RefreshTTL: cfg.RefreshTokenTTL},
		Docs:    cfg.DocsEnabled,
		Version: version,
	})

	// --- Startup probes: fail fast (fail-closed, S-07) ---------------------
	if err := probeStartup(log, dir, sessions, users); err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		log.Info().Str("addr", cfg.ListenAddr).Bool("docs", cfg.DocsEnabled).Msg("http server listening")
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return fmt.Errorf("http server: %w", err)
	case <-ctx.Done():
		log.Info().Msg("shutdown signal received")
	}

	// Graceful shutdown: stop accepting, drain in-flight requests (S: reliability).
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Error().Err(err).Msg("graceful shutdown incomplete")
	}
	log.Info().Msg("bye")
	return nil
}

func probeStartup(log zerolog.Logger, dir Directory, sessions SessionPinger, users UserPinger) error {
	// A few quick retries so container start order (redis/pg slower than api)
	// does not crash-loop the service; afterwards fail for the orchestrator.
	deadline := time.Now().Add(30 * time.Second)
	var lastErr error
	for {
		lastErr = checkAll(dir, sessions, users)
		if lastErr == nil {
			log.Info().Msg("all backend dependencies are reachable (ldap, redis, postgres)")
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("startup probe failed: %w", lastErr)
		}
		log.Warn().Err(lastErr).Msg("backend not ready yet, retrying")
		time.Sleep(2 * time.Second)
	}
}

// The interfaces below keep main decoupled from concrete types in tests.
type Directory interface{ Ping() error }
type SessionPinger interface {
	Ping(ctx context.Context) error
}
type UserPinger interface {
	Ping(ctx context.Context) error
}

func checkAll(dir Directory, sessions SessionPinger, users UserPinger) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := dir.Ping(); err != nil {
		return fmt.Errorf("ldap: %w", err)
	}
	if err := sessions.Ping(ctx); err != nil {
		return fmt.Errorf("redis: %w", err)
	}
	return users.Ping(ctx)
}

func newLogger(cfg *config.Config) zerolog.Logger {
	level, err := zerolog.ParseLevel(cfg.LogLevel)
	if err != nil {
		level = zerolog.InfoLevel
	}
	zerolog.SetGlobalLevel(level)
	zerolog.TimestampFieldName = "ts"
	if cfg.LogFormat == "console" {
		return zerolog.New(zerolog.ConsoleWriter{Out: os.Stderr, TimeFormat: time.RFC3339}).
			With().Timestamp().Logger()
	}
	return zerolog.New(os.Stderr).With().Timestamp().Logger()
}

// version is set at build time via -ldflags "-X main.version=..."; dev uses "dev".
var version = "dev"
