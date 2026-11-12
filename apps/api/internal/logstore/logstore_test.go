package logstore

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDailyWriterRotatesAndReads(t *testing.T) {
	dir := t.TempDir()
	w, err := NewDailyWriter(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(`{"level":"info","event":"login","message":"a"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte("not-json\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write([]byte(`{"level":"error","event":"refresh","message":"b"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()

	today := time.Now().Format("2006-01-02")
	items, next, err := Read(dir, today, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	// malformed line is skipped, not fatal
	if len(items) != 2 {
		t.Fatalf("want 2 parsed entries, got %d", len(items))
	}
	if next != 0 {
		t.Fatalf("next = %d, want 0 (file exhausted)", next)
	}
	if items[0]["event"] != "login" || items[1]["level"] != "error" {
		t.Fatalf("entries wrong: %+v", items)
	}

	// pagination: offset counts RAW lines; page2.next=0 when the last raw
	// line is consumed, even if a malformed line was skipped on the way.
	page1, next, err := Read(dir, today, 0, 1)
	if err != nil || len(page1) != 1 || next == 0 {
		t.Fatalf("page1: %d items next=%d err=%v", len(page1), next, err)
	}
	page2, next2, _ := Read(dir, today, next, 1)
	if len(page2) != 1 || next2 != 0 { // malformed line skipped, refresh lands here, file ends
		t.Fatalf("page2: %d items next=%d", len(page2), next2)
	}
}

func TestDatesNewestFirst(t *testing.T) {
	dir := t.TempDir()
	for _, d := range []string{"20261110", "20261112", "20261111"} {
		name := "aps-" + d + ".log"
		if err := os.WriteFile(filepath.Join(dir, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// unrelated files must be ignored
	if err := os.WriteFile(filepath.Join(dir, "other.txt"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	dates, err := Dates(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(dates) != 3 || dates[0] != "2026-11-12" || dates[2] != "2026-11-10" {
		t.Fatalf("dates = %v", dates)
	}
}

func TestSweepRemovesOldFiles(t *testing.T) {
	dir := t.TempDir()
	old := "aps-" + time.Now().AddDate(0, 0, -4).Format("20060102") + ".log"
	fresh := "aps-" + time.Now().Format("20060102") + ".log"
	for _, n := range []string{old, fresh} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("{}\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// backdate the old file's name is enough — Sweep uses the filename date
	removed, err := Sweep(dir, 3)
	if err != nil {
		t.Fatal(err)
	}
	if len(removed) != 1 || removed[0] != old {
		t.Fatalf("removed = %v, want [%s]", removed, old)
	}
	if _, err := os.Stat(filepath.Join(dir, fresh)); err != nil {
		t.Fatal("fresh file must survive")
	}
}

func TestReadRejectsBadDate(t *testing.T) {
	dir := t.TempDir()
	if _, _, err := Read(dir, "../../etc", 0, 10); err == nil {
		t.Fatal("path traversal date must be rejected")
	}
	if _, _, err := Read(dir, "2026-01-01", 0, 10); err != ErrNoFile {
		t.Fatalf("missing file: %v", err)
	}
}

func TestRetentionWorkerSweeps(t *testing.T) {
	dir := t.TempDir()
	old := "aps-" + time.Now().AddDate(0, 0, -10).Format("20060102") + ".log"
	if err := os.WriteFile(filepath.Join(dir, old), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	stop := StartRetention(ctx, dir, 3, nil)
	defer stop()
	cancel()
	stop() // wait for the initial sweep
	if _, err := os.Stat(filepath.Join(dir, old)); !os.IsNotExist(err) {
		t.Fatal("retention worker must remove old files at startup")
	}
}
