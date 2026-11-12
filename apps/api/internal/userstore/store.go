// Package userstore implements the PostgreSQL-backed user profile cache
// using GORM (most popular Go ORM: big community, docs, built-in soft
// delete and timestamps).
//
// Scope decision: AD remains the source of truth (ТЗ 2.2). This store keeps
// a local copy of profiles for /me lookups and admin listing without
// hitting LDAP. Rows are upserted on every successful login; soft delete
// (deleted_at) marks a profile as removed locally, and the next login
// re-activates it. Passwords are NEVER stored (S-03, S-09).
package userstore

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
	"gorm.io/gorm/logger"

	"aps.local/apps/api/internal/ldap"
)

// ErrNotFound means no matching profile row exists.
var ErrNotFound = errors.New("user not found")

// User is the GORM model and API projection of a stored profile.
// Timestamps: CreatedAt/UpdatedAt are managed by GORM; DeletedAt is the
// standard GORM soft-delete column (NULL = active).
type User struct {
	ID          uuid.UUID      `gorm:"type:uuid;primaryKey" json:"id"`
	Username    string         `gorm:"uniqueIndex;size:255;not null" json:"username"`
	DN          string         `gorm:"size:1024;not null" json:"-"`
	DisplayName string         `gorm:"size:512;not null;default:''" json:"display_name"`
	Email       string         `gorm:"size:512;not null;default:''" json:"email"`
	Roles       pq.StringArray `gorm:"type:text[];not null;default:'{}'" json:"roles"`
	LastLoginAt *time.Time     `json:"last_login_at"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

// Store is the GORM-backed repository.
type Store struct {
	db *gorm.DB
}

func New(db *gorm.DB) *Store { return &Store{db: db} }

// Open connects via GORM and tunes the connection pool.
func Open(dsn string, maxConns int) (*gorm.DB, error) {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger:  logger.Discard, // app logs via zerolog; avoid leaking data
		NowFunc: func() time.Time { return time.Now().UTC() },
	})
	if err != nil {
		return nil, err
	}
	sqlDB, err := db.DB()
	if err != nil {
		return nil, err
	}
	if maxConns < 1 {
		maxConns = 10
	}
	sqlDB.SetMaxOpenConns(maxConns)
	sqlDB.SetMaxIdleConns(maxConns / 2)
	sqlDB.SetConnMaxLifetime(time.Hour)
	return db, nil
}

// NewUUIDv7 generates the primary key (UUID version 7 — time-ordered).
func NewUUIDv7() uuid.UUID {
	id, err := uuid.NewV7()
	if err != nil {
		panic("uuid v7: " + err.Error()) // crypto/rand failure is unrecoverable
	}
	return id
}

// UpsertFromLogin inserts or refreshes a profile after successful
// authentication. Reactivation: a soft-deleted profile becomes active
// again (AD confirmed the user is real and authentic).
func (s *Store) UpsertFromLogin(ctx context.Context, u *ldap.User) (*User, error) {
	now := time.Now().UTC()
	row := &User{
		ID:          NewUUIDv7(),
		Username:    u.Username,
		DN:          u.DN,
		DisplayName: u.DisplayName,
		Email:       u.Email,
		Roles:       pq.StringArray(u.Roles),
		LastLoginAt: &now,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	err := s.db.WithContext(ctx).Clauses(clause.OnConflict{
		Columns: []clause.Column{{Name: "username"}},
		DoUpdates: clause.Assignments(map[string]any{
			"dn":            u.DN,
			"display_name":  u.DisplayName,
			"email":         u.Email,
			"roles":         pq.StringArray(u.Roles),
			"last_login_at": now,
			"updated_at":    now,
			"deleted_at":    gorm.Expr("NULL"), // re-activate on login
		}),
	}).Create(row).Error
	if err != nil {
		return nil, err
	}
	return row, nil
}

// GetByUsername returns the profile row regardless of deletion status.
func (s *Store) GetByUsername(ctx context.Context, username string) (*User, error) {
	var u User
	err := s.db.WithContext(ctx).Unscoped().Where("username = ?", username).First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// GetActiveByUsername returns the profile only if not soft-deleted
// (default GORM scope applies `deleted_at IS NULL`).
func (s *Store) GetActiveByUsername(ctx context.Context, username string) (*User, error) {
	var u User
	err := s.db.WithContext(ctx).Where("username = ?", username).First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// GetByID returns the profile by primary key (active only).
func (s *Store) GetByID(ctx context.Context, id uuid.UUID) (*User, error) {
	var u User
	err := s.db.WithContext(ctx).Where("id = ?", id).First(&u).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

// ListFilter narrows the admin listing (GET /users).
type ListFilter struct {
	Query  string // substring across username / display_name / email
	Status string // "active" (default) | "deleted" | "all"
	Role   string // exact role match, optional
	Limit  int    // 1..200, default 50
	Cursor string // keyset: last username of the previous page
}

// List returns profiles ordered by username with keyset pagination.
func (s *Store) List(ctx context.Context, f ListFilter) ([]User, string, error) {
	if f.Limit < 1 || f.Limit > 200 {
		f.Limit = 50
	}
	q := s.db.WithContext(ctx).Model(&User{})

	switch strings.ToLower(f.Status) {
	case "deleted":
		q = q.Unscoped().Where("deleted_at IS NOT NULL")
	case "all":
		q = q.Unscoped()
	default: // active
		// default scope: deleted_at IS NULL
	}
	if sQuery := strings.TrimSpace(f.Query); sQuery != "" {
		p := `%` + escapeLike(sQuery) + `%`
		q = q.Where("username ILIKE ? OR display_name ILIKE ? OR email ILIKE ?", p, p, p)
	}
	if r := strings.TrimSpace(f.Role); r != "" {
		q = q.Where("roles @> ?", pq.StringArray{r})
	}
	if f.Cursor != "" {
		q = q.Where("username > ?", f.Cursor)
	}

	var users []User
	if err := q.Order("username ASC").Limit(f.Limit + 1).Find(&users).Error; err != nil {
		return nil, "", err
	}
	next := ""
	if len(users) > f.Limit {
		next = users[f.Limit-1].Username
		users = users[:f.Limit]
	}
	return users, next, nil
}

// SoftDelete marks the profile deleted (GORM soft delete sets deleted_at
// and updated_at). Idempotent: deleting an already-deleted row reports
// ErrNotFound.
func (s *Store) SoftDelete(ctx context.Context, id uuid.UUID) error {
	res := s.db.WithContext(ctx).Where("id = ? AND deleted_at IS NULL", id).Delete(&User{})
	if res.Error != nil {
		return res.Error
	}
	if res.RowsAffected == 0 {
		return ErrNotFound
	}
	return nil
}

// Ping verifies DB reachability (/ready, S-07 fail-closed).
func (s *Store) Ping(ctx context.Context) error {
	var one int
	return s.db.WithContext(ctx).Raw("SELECT 1").Scan(&one).Error
}

// Close releases the pool.
func (s *Store) Close() {
	if sqlDB, err := s.db.DB(); err == nil {
		_ = sqlDB.Close()
	}
}

// escapeLike neutralises LIKE wildcards in user input.
func escapeLike(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return r.Replace(s)
}
