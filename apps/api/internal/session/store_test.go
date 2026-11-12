package session

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func newTestStore(t *testing.T) (*Store, *miniredis.Miniredis) {
	t.Helper()
	mr := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: mr.Addr()})
	s := New(rdb, "testaps:", 168*time.Hour)
	t.Cleanup(func() { _ = rdb.Close() })
	return s, mr
}

func testSession(fid, jti, username string) *Session {
	return &Session{
		FamilyID:  fid,
		JTI:       jti,
		Username:  username,
		UserAgent: "test-agent",
		IP:        "10.0.0.1",
		CreatedAt: time.Now().UTC().Truncate(time.Second),
		Roles:     []string{"admin"},
		DN:        "CN=alice,OU=users,DC=mca,DC=local",
	}
}

func TestCreateAndGetFamily(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()

	sess := testSession("fam1", "jti1", "alice")
	if err := s.Create(ctx, sess); err != nil {
		t.Fatal(err)
	}
	info, err := s.GetFamily(ctx, "fam1")
	if err != nil {
		t.Fatal(err)
	}
	if info.Username != "alice" || info.IP != "10.0.0.1" || info.UserAgent != "test-agent" {
		t.Fatalf("unexpected family info: %+v", info)
	}
	if info.CreatedAt.IsZero() {
		t.Fatal("created_at must be set")
	}
}

// S-04: happy rotation replaces the grant atomically.
func TestRotateHappyPath(t *testing.T) {
	s, mr := newTestStore(t)
	ctx := context.Background()

	_ = s.Create(ctx, testSession("fam1", "jti1", "alice"))
	newSess := testSession("fam1", "jti2", "alice")
	newSess.CreatedAt = time.Now().Add(-time.Hour)
	if err := s.Rotate(ctx, "fam1", "jti1", newSess); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	// old grant deleted
	if mr.Exists("testaps:rt:jti1") {
		t.Fatal("old jti record must be deleted")
	}
	// new grant exists
	if !mr.Exists("testaps:rt:jti2") {
		t.Fatal("new jti record missing")
	}
	// family points to the new grant
	cur := mr.HGet("testaps:fam:fam1", "j")
	if cur != "jti2" {
		t.Fatalf("family jti = %q, want jti2", cur)
	}
}

// S-04 acceptance #3: reuse of an already-used refresh token returns replay
// and invalidates the entire family.
func TestReplayRevokesFamily(t *testing.T) {
	s, mr := newTestStore(t)
	ctx := context.Background()

	_ = s.Create(ctx, testSession("fam1", "jti1", "alice"))
	newSess := testSession("fam1", "jti2", "alice")
	if err := s.Rotate(ctx, "fam1", "jti1", newSess); err != nil {
		t.Fatal(err)
	}

	// second use of the SAME old token => replay
	err := s.Rotate(ctx, "fam1", "jti1", testSession("fam1", "jti3", "alice"))
	if !errors.Is(err, ErrReplay) {
		t.Fatalf("want ErrReplay, got %v", err)
	}
	// whole family gone
	if mr.Exists("testaps:fam:fam1") {
		t.Fatal("family must be revoked")
	}
	if mr.Exists("testaps:rt:jti2") {
		t.Fatal("live grant of the family must be revoked")
	}
	if _, err := s.GetFamily(ctx, "fam1"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("GetFamily = %v, want ErrSessionNotFound", err)
	}
}

// Rotation with a mismatching family id is treated as replay (fail-closed).
func TestRotateWithForeignFamily(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	_ = s.Create(ctx, testSession("fam1", "jti1", "alice"))
	err := s.Rotate(ctx, "fam-other", "jti1", testSession("fam-other", "jti9", "mallory"))
	if !errors.Is(err, ErrReplay) {
		t.Fatalf("want ErrReplay, got %v", err)
	}
}

func TestRevokeFamilyIdempotent(t *testing.T) {
	s, mr := newTestStore(t)
	ctx := context.Background()
	_ = s.Create(ctx, testSession("fam1", "jti1", "alice"))

	if err := s.RevokeFamily(ctx, "fam1"); err != nil {
		t.Fatal(err)
	}
	if mr.Exists("testaps:fam:fam1") || mr.Exists("testaps:rt:jti1") {
		t.Fatal("family data must be gone")
	}
	if err := s.RevokeFamily(ctx, "fam1"); err != nil {
		t.Fatalf("second revoke must be a no-op, got %v", err)
	}
}

func TestRevokeUserSessions(t *testing.T) {
	s, mr := newTestStore(t)
	ctx := context.Background()
	_ = s.Create(ctx, testSession("fam1", "jti1", "alice"))
	_ = s.Create(ctx, testSession("fam2", "jti2", "alice"))
	_ = s.Create(ctx, testSession("fam3", "jti3", "bob"))

	if err := s.RevokeUserSessions(ctx, "alice"); err != nil {
		t.Fatal(err)
	}
	if mr.Exists("testaps:fam:fam1") || mr.Exists("testaps:fam:fam2") {
		t.Fatal("alice families must be revoked")
	}
	if !mr.Exists("testaps:fam:fam3") {
		t.Fatal("bob's family must survive")
	}
}

func TestListByUserPagination(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	base := time.Now().Add(-24 * time.Hour)
	for i := 0; i < 5; i++ {
		sess := testSession("fam"+string(rune('a'+i)), "jti"+string(rune('a'+i)), "alice")
		sess.CreatedAt = base.Add(time.Duration(i) * time.Minute)
		if err := s.Create(ctx, sess); err != nil {
			t.Fatal(err)
		}
	}

	page1, next, err := s.ListByUser(ctx, "alice", 2, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(page1) != 2 || next == "" {
		t.Fatalf("page1 = %d items, next=%q", len(page1), next)
	}
	if page1[0].ID != "fama" || page1[1].ID != "famb" {
		t.Fatalf("unexpected order: %v,%v", page1[0].ID, page1[1].ID)
	}

	page2, next2, err := s.ListByUser(ctx, "alice", 2, next)
	if err != nil {
		t.Fatal(err)
	}
	if len(page2) != 2 || page2[0].ID != "famc" || page2[1].ID != "famd" {
		t.Fatalf("page2 wrong: %+v", page2)
	}

	page3, next3, _ := s.ListByUser(ctx, "alice", 2, next2)
	if len(page3) != 1 || page3[0].ID != "fame" || next3 != "" {
		t.Fatalf("page3 wrong: %+v next=%q", page3, next3)
	}
}

func TestListAllAcrossUsers(t *testing.T) {
	s, _ := newTestStore(t)
	ctx := context.Background()
	_ = s.Create(ctx, testSession("fam1", "jti1", "alice"))
	_ = s.Create(ctx, testSession("fam2", "jti2", "bob"))

	items, next, err := s.ListAll(ctx, 50, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 {
		t.Fatalf("want 2 sessions, got %d", len(items))
	}
	if next != "" {
		t.Fatalf("single page should have no cursor, got %q", next)
	}
}

func TestPing(t *testing.T) {
	s, mr := newTestStore(t)
	if err := s.Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	mr.Close()
	if err := s.Ping(context.Background()); err == nil {
		t.Fatal("ping after close must fail")
	}
}
