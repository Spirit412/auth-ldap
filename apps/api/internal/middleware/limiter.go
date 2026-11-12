package middleware

import (
	"context"
	"strings"
	"time"

	"github.com/go-redis/redis_rate/v10"
	"github.com/redis/go-redis/v9"

	"aps.local/apps/api/internal/auth"
)

// Limiter implements auth.RateLimiter with GCRA counters in Redis
// (go-redis/redis_rate). Counters live in the shared Redis instance, so
// limits hold across all APS instances behind an LB (S-06/F-10).
type Limiter struct {
	login   redis_rate.Limit
	refresh redis_rate.Limit
	gcra    *redis_rate.Limiter
	keyPfx  string
}

func NewLimiter(rdb redis.UniversalClient, keyPrefix string, login int, loginWin, refreshWin time.Duration) *Limiter {
	if keyPrefix == "" {
		keyPrefix = "aps:"
	}
	return &Limiter{
		// Rate = событий за Period; без него GCRA-скрипт получает деление
		// на ноль и падает с "value is not an integer" (S-06).
		login:   redis_rate.Limit{Burst: login, Rate: login, Period: loginWin},
		refresh: redis_rate.Limit{Burst: 10, Rate: 10, Period: refreshWin},
		gcra:    redis_rate.NewLimiter(rdb),
		keyPfx:  keyPrefix,
	}
}

func (l *Limiter) allow(ctx context.Context, key string, limit redis_rate.Limit) (time.Duration, bool, error) {
	res, err := l.gcra.Allow(ctx, key, limit)
	if err != nil {
		// S-07 fail-closed: Redis unavailable -> deny with 503 upstream.
		return 0, false, err
	}
	if res.Allowed > 0 {
		return 0, true, nil
	}
	return res.RetryAfter, false, nil
}

// AllowLogin limits by IP+username (lowercased, so "Alice" and "alice"
// share a bucket and an attacker cannot multiply attempts via case).
func (l *Limiter) AllowLogin(ctx context.Context, ip, username string) (time.Duration, bool, error) {
	key := l.keyPfx + "rl:login:" + ip + ":" + strings.ToLower(username)
	return l.allow(ctx, key, l.login)
}

// AllowRefresh limits by user id.
func (l *Limiter) AllowRefresh(ctx context.Context, userID string) (time.Duration, bool, error) {
	key := l.keyPfx + "rl:refresh:" + strings.ToLower(userID)
	return l.allow(ctx, key, l.refresh)
}

// compile-time interface check
var _ auth.RateLimiter = (*Limiter)(nil)
