// Package session implements the Redis-backed refresh-token store.
//
// Data model (prefix is configurable, default "aps:", because Redis is
// shared with other services on this host):
//
//	<prefix>rt:<jti>        JSON Session   — live refresh grant (TTL)
//	<prefix>fam:<family_id> hash           — session record: current jti, meta
//	<prefix>user:<username> zset           — family_id -> created_at ms (index)
//
// Security decisions (S-04):
//   - Rotation is atomic via WATCH/MULTI/EXEC (CAS). The winner deletes the
//     old jti record and installs the new one in one transaction.
//   - A losing concurrent rotation re-runs, finds the old key missing and
//     treats it as REPLAY: the whole family is revoked. Presenting an
//     already-used refresh token therefore invalidates the entire chain.
//   - Replay revocation also removes the family hash and the user index
//     entry; any orphaned rt key remains unreachable because every use
//     re-triggers replay revocation first (fail-closed).
package session

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

var (
	// ErrReplay means the presented refresh token was already used or is
	// unknown — the family has been (or is being) revoked.
	ErrReplay = errors.New("refresh replay detected")
	// ErrSessionNotFound means the session family does not exist (expired or revoked).
	ErrSessionNotFound = errors.New("session not found")
)

// Session is a stored refresh session (one browser/programmatic session).
type Session struct {
	FamilyID    string    `json:"f"`
	JTI         string    `json:"j"`
	Username    string    `json:"u"`
	UserAgent   string    `json:"ua"`
	IP          string    `json:"ip"`
	CreatedAt   time.Time `json:"ca"`
	Roles       []string  `json:"roles,omitempty"`
	DN          string    `json:"dn,omitempty"`
	DisplayName string    `json:"name,omitempty"`
	Email       string    `json:"email,omitempty"`
}

// Store persists refresh grants in Redis.
type Store struct {
	rdb    redis.UniversalClient
	prefix string
	ttl    time.Duration
}

func New(rdb redis.UniversalClient, prefix string, refreshTTL time.Duration) *Store {
	if prefix == "" {
		prefix = "aps:"
	}
	return &Store{rdb: rdb, prefix: prefix, ttl: refreshTTL}
}

func (s *Store) rtKey(jti string) string  { return s.prefix + "rt:" + jti }
func (s *Store) famKey(fid string) string { return s.prefix + "fam:" + fid }
func (s *Store) userKey(u string) string  { return s.prefix + "user:" + u }

func rtVal(sess *Session) (string, error) {
	b, err := json.Marshal(sess)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Create persists a brand-new session family with its first refresh grant.
func (s *Store) Create(ctx context.Context, sess *Session) error {
	val, err := rtVal(sess)
	if err != nil {
		return err
	}
	pipe := s.rdb.Pipeline()
	pipe.Set(ctx, s.rtKey(sess.JTI), val, s.ttl)
	pipe.HSet(ctx, s.famKey(sess.FamilyID), map[string]any{
		"u":  sess.Username,
		"ua": sess.UserAgent,
		"ip": sess.IP,
		"ca": sess.CreatedAt.UnixMilli(),
		"j":  sess.JTI,
		"r":  strings.Join(sess.Roles, ","),
		"dn": sess.DN,
		"n":  sess.DisplayName,
		"e":  sess.Email,
	})
	pipe.Expire(ctx, s.famKey(sess.FamilyID), s.ttl)
	pipe.ZAdd(ctx, s.userKey(sess.Username), redis.Z{Score: float64(sess.CreatedAt.UnixMilli()), Member: sess.FamilyID})
	pipe.Expire(ctx, s.userKey(sess.Username), s.ttl)
	_, err = pipe.Exec(ctx)
	return err
}

// Rotate atomically replaces oldJTI with newSess.JTI inside the family.
//
// Semantics:
//   - happy path: old grant deleted + new grant installed in one CAS txn;
//   - the presented jti is missing or mismatches the family's current jti:
//     REPLAY -> the entire family (hash, index entry, current grant) is
//     revoked in the same transaction and ErrReplay is returned.
func (s *Store) Rotate(ctx context.Context, familyID, oldJTI string, newSess *Session) error {
	const maxAttempts = 5
	for attempt := 0; attempt < maxAttempts; attempt++ {
		err := s.rotateOnce(ctx, familyID, oldJTI, newSess)
		if errors.Is(err, redis.TxFailedErr) {
			continue // concurrent rotation lost the race — re-check state
		}
		return err
	}
	return fmt.Errorf("session rotate: too many CAS retries: %w", ErrReplay)
}

func (s *Store) rotateOnce(ctx context.Context, familyID, oldJTI string, newSess *Session) error {
	famKey := s.famKey(familyID)
	userKey := s.userKey(newSess.Username)

	val, err := rtVal(newSess)
	if err != nil {
		return err
	}

	txf := func(tx *redis.Tx) error {
		// Live grant record for the presented token.
		raw, err := tx.Get(ctx, s.rtKey(oldJTI)).Result()
		if err == redis.Nil {
			return s.replayInTxn(ctx, tx, familyID)
		}
		if err != nil {
			return err
		}
		var old Session
		if err := json.Unmarshal([]byte(raw), &old); err != nil || old.FamilyID != familyID {
			// Corrupt record or family mismatch — treat as replay (fail-closed).
			return s.replayInTxn(ctx, tx, familyID)
		}
		// Family must exist and reference exactly this grant.
		cur, err := tx.HGet(ctx, famKey, "j").Result()
		if err == redis.Nil {
			return s.replayInTxn(ctx, tx, familyID)
		}
		if err != nil {
			return err
		}
		if cur != oldJTI {
			return s.replayInTxn(ctx, tx, familyID)
		}

		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.Del(ctx, s.rtKey(oldJTI))
			pipe.Set(ctx, s.rtKey(newSess.JTI), val, s.ttl)
			pipe.HSet(ctx, famKey, "j", newSess.JTI)
			pipe.Expire(ctx, famKey, s.ttl)
			pipe.Expire(ctx, userKey, s.ttl)
			return nil
		})
		return err
	}
	return s.rdb.Watch(ctx, txf, s.rtKey(oldJTI), famKey)
}

// replayInTxn revokes the whole family inside the CAS transaction:
// family hash, the live grant it references, and the user index entry.
func (s *Store) replayInTxn(ctx context.Context, tx *redis.Tx, familyID string) error {
	famKey := s.famKey(familyID)
	fam, err := tx.HGetAll(ctx, famKey).Result()
	if err != nil {
		return err
	}
	_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
		pipe.Del(ctx, famKey)
		if j, ok := fam["j"]; ok && j != "" {
			pipe.Del(ctx, s.rtKey(j))
		}
		if u, ok := fam["u"]; ok && u != "" {
			pipe.ZRem(ctx, s.userKey(u), familyID)
		}
		return nil
	})
	if err != nil {
		return err
	}
	return ErrReplay
}

// RevokeFamily removes the session family and its live grant. Idempotent.
func (s *Store) RevokeFamily(ctx context.Context, familyID string) error {
	famKey := s.famKey(familyID)
	fam, err := s.rdb.HGetAll(ctx, famKey).Result()
	if err != nil {
		return err
	}
	pipe := s.rdb.Pipeline()
	pipe.Del(ctx, famKey)
	if j := fam["j"]; j != "" {
		pipe.Del(ctx, s.rtKey(j))
	}
	if u := fam["u"]; u != "" {
		pipe.ZRem(ctx, s.userKey(u), familyID)
	}
	_, err = pipe.Exec(ctx)
	return err
}

// RevokeUserSessions revokes every session of the given user (used when an
// admin soft-deletes a profile).
func (s *Store) RevokeUserSessions(ctx context.Context, username string) error {
	fids, err := s.rdb.ZRange(ctx, s.userKey(username), 0, -1).Result()
	if err != nil {
		return err
	}
	for _, fid := range fids {
		if err := s.RevokeFamily(ctx, fid); err != nil {
			return err
		}
	}
	return nil
}

// Ping verifies Redis reachability (/ready, S-07 fail-closed).
func (s *Store) Ping(ctx context.Context) error {
	return s.rdb.Ping(ctx).Err()
}

// GetFamily returns session metadata by family id (admin list/delete).
func (s *Store) GetFamily(ctx context.Context, familyID string) (*SessionInfo, error) {
	fam, err := s.rdb.HGetAll(ctx, s.famKey(familyID)).Result()
	if err != nil {
		return nil, err
	}
	if len(fam) == 0 {
		return nil, ErrSessionNotFound
	}
	return famToInfo(familyID, fam)
}

// SessionInfo is the admin-visible projection of a session family, plus
// the attributes the refresh flow needs (roles/DN/profile) without LDAP.
type SessionInfo struct {
	ID          string    `json:"id"`
	Username    string    `json:"username"`
	CreatedAt   time.Time `json:"created_at"`
	UserAgent   string    `json:"user_agent"`
	IP          string    `json:"ip"`
	Roles       []string  `json:"-"` // internal: reused on refresh
	DN          string    `json:"-"` // internal: AD identity for role re-check
	DisplayName string    `json:"-"` // internal: carried into new access tokens
	Email       string    `json:"-"`
}

func famToInfo(id string, fam map[string]string) (*SessionInfo, error) {
	info := &SessionInfo{
		ID:          id,
		Username:    fam["u"],
		UserAgent:   fam["ua"],
		IP:          fam["ip"],
		DN:          fam["dn"],
		DisplayName: fam["n"],
		Email:       fam["e"],
	}
	if fam["r"] != "" {
		info.Roles = strings.Split(fam["r"], ",")
	}
	if ms, err := strconv.ParseInt(fam["ca"], 10, 64); err == nil {
		info.CreatedAt = time.UnixMilli(ms).UTC()
	}
	return info, nil
}

// ListByUser returns sessions for the given username with cursor pagination.
// Cursor is "<created_ms>:<family_id>"; ordering is by creation time.
func (s *Store) ListByUser(ctx context.Context, username string, limit int, cursor string) ([]SessionInfo, string, error) {
	if limit < 1 || limit > 200 {
		limit = 50
	}
	userKey := s.userKey(username)
	var lastScore int64
	var lastFID string
	if cursor != "" {
		if ms, fid, ok := parseCursor(cursor); ok {
			lastScore = ms
			lastFID = fid
		}
	}

	// A user holds few sessions — fetch all and seek in memory (sorted by
	// score asc, then member for stable tie handling).
	zs, err := s.rdb.ZRangeWithScores(ctx, userKey, 0, -1).Result()
	if err != nil {
		return nil, "", err
	}
	sortZ := make([]redis.Z, len(zs))
	copy(sortZ, zs)
	sort.Slice(sortZ, func(i, j int) bool {
		if sortZ[i].Score != sortZ[j].Score {
			return sortZ[i].Score < sortZ[j].Score
		}
		return sortZ[i].Member.(string) < sortZ[j].Member.(string)
	})

	items := make([]SessionInfo, 0, limit)
	var next string
	for _, z := range sortZ {
		fid := z.Member.(string)
		score := int64(z.Score)
		// Seek semantics: drop entries at/before the cursor position.
		if score < lastScore || (score == lastScore && fid <= lastFID) {
			continue
		}
		info, err := s.GetFamily(ctx, fid)
		if errors.Is(err, ErrSessionNotFound) {
			continue // expired concurrently — skip
		}
		if err != nil {
			return nil, "", err
		}
		items = append(items, *info)
		if len(items) == limit {
			next = strconv.FormatInt(score, 10) + ":" + fid
			break
		}
	}
	return items, next, nil
}

func zRangeMin(min float64) string {
	if math.IsInf(min, -1) {
		return "-inf"
	}
	return "(" + strconv.FormatFloat(min, 'f', -1, 64) // exclusive
}

// ListAll lists sessions across all users (admin dashboard). The cursor is
// the Redis SCAN position ("0" or "" = start); when the scan completes the
// returned cursor is empty. Ordering within a page is by creation time.
func (s *Store) ListAll(ctx context.Context, limit int, cursor string) ([]SessionInfo, string, error) {
	if limit < 1 || limit > 200 {
		limit = 50
	}
	start := uint64(0)
	if cursor != "" {
		v, err := strconv.ParseUint(cursor, 10, 64)
		if err != nil {
			return nil, "", fmt.Errorf("bad cursor: %w", ErrSessionNotFound)
		}
		start = v
	}

	var fids []string
	seen := make(map[string]struct{})
	next := ""
	iter := uint64(start)
	for {
		keys, nextIter, err := s.rdb.Scan(ctx, iter, s.prefix+"user:*", 200).Result()
		if err != nil {
			return nil, "", err
		}
		for _, k := range keys {
			zs, err := s.rdb.ZRangeWithScores(ctx, k, 0, -1).Result()
			if err != nil {
				return nil, "", err
			}
			for _, z := range zs {
				fid := z.Member.(string)
				if _, ok := seen[fid]; ok {
					continue
				}
				seen[fid] = struct{}{}
				fids = append(fids, fid)
			}
		}
		iter = nextIter
		if iter == 0 || len(fids) >= limit*8 { // bound work per request
			break
		}
	}
	if iter != 0 {
		next = strconv.FormatUint(iter, 10)
	}

	items := make([]SessionInfo, 0, len(fids))
	for _, fid := range fids {
		info, err := s.GetFamily(ctx, fid)
		if errors.Is(err, ErrSessionNotFound) {
			continue
		}
		if err != nil {
			return nil, "", err
		}
		items = append(items, *info)
	}
	sort.Slice(items, func(i, j int) bool {
		if !items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].CreatedAt.Before(items[j].CreatedAt)
		}
		return items[i].ID < items[j].ID
	})
	if len(items) > limit {
		items = items[:limit]
		if next == "" {
			// Scan finished but items were truncated — hint clients to ask
			// again (cursor stays "0"; additional signalling is unnecessary
			// for the admin UI use case).
			next = "0-resume"
		}
	}
	return items, next, nil
}

func parseCursor(c string) (int64, string, bool) {
	i := strings.IndexByte(c, ':')
	if i <= 0 {
		return 0, "", false
	}
	ms, err := strconv.ParseInt(c[:i], 10, 64)
	if err != nil {
		return 0, "", false
	}
	return ms, c[i+1:], true
}
