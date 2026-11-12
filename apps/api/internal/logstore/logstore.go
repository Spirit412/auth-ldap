// Package logstore manages the on-disk admin log files: one JSON-lines
// file per day (aps-YYYYMMDD.log), retention sweeping (files older than N
// days are deleted), and reads for the admin log viewer.
//
// Design decisions:
//   - The date lives in the FILENAME, not in mtime: retention and listing
//     are exact even if the file is touched constantly.
//   - Only names matching aps-YYYYMMDD.log are ever read or deleted — the
//     directory may hold unrelated files, and path traversal from the API
//     layer is impossible because the date is validated as a real calendar
//     date before any filesystem access.
package logstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var fileNameRe = regexp.MustCompile(`^aps-(\d{4})(\d{2})(\d{2})\.log$`)

var (
	ErrBadDate = errors.New("bad date")
	ErrNoFile  = errors.New("log file not found")
)

// Entry is one parsed JSON log line; unknown fields are preserved.
type Entry map[string]any

// DailyWriter appends to aps-YYYYMMDD.log and transparently re-opens the
// file when the local date changes.
type DailyWriter struct {
	dir string
	mu  sync.Mutex
	day string
	f   *os.File
}

// NewDailyWriter returns an io.Writer that appends to aps-YYYYMMDD.log,
// transparently switching files at date change.
func NewDailyWriter(dir string) (*DailyWriter, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}
	return &DailyWriter{dir: dir}, nil
}

func (w *DailyWriter) Write(p []byte) (int, error) {
	day := time.Now().Format("20060102")
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f == nil || w.day != day {
		if w.f != nil {
			_ = w.f.Close()
		}
		f, err := os.OpenFile(filepath.Join(w.dir, "aps-"+day+".log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o640)
		if err != nil {
			return 0, err
		}
		w.f, w.day = f, day
	}
	return w.f.Write(p)
}

func (w *DailyWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.f != nil {
		return w.f.Close()
	}
	return nil
}

// Sweep deletes aps-YYYYMMDD.log files older than days. Returns the names
// removed (for logging by the caller).
func Sweep(dir string, days int) ([]string, error) {
	if days < 1 {
		days = 3
	}
	cutoff := time.Now().AddDate(0, 0, -days)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var removed []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		day, ok := parseNameDate(e.Name())
		if !ok {
			continue
		}
		if day.Before(cutoff) {
			if err := os.Remove(filepath.Join(dir, e.Name())); err == nil {
				removed = append(removed, e.Name())
			}
		}
	}
	return removed, nil
}

// StartRetention sweeps once at startup and then every hour until ctx is
// done. Returns a stop function.
func StartRetention(ctx context.Context, dir string, days int, onSweep func(removed []string, err error)) (stop func()) {
	done := make(chan struct{})
	go func() {
		defer close(done)
		run := func() {
			removed, err := Sweep(dir, days)
			if onSweep != nil {
				onSweep(removed, err)
			}
		}
		run()
		t := time.NewTicker(time.Hour)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				run()
			}
		}
	}()
	return func() { <-done }
}

// Dates lists available log dates, newest first.
func Dates(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var dates []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if day, ok := parseNameDate(e.Name()); ok {
			dates = append(dates, day.Format("2006-01-02"))
		}
	}
	sort.Sort(sort.Reverse(sort.StringSlice(dates)))
	return dates, nil
}

// Read parses a day's JSON lines, skipping malformed ones. offset/limit
// address the RAW line number (offset 0 = from the beginning); nextOffset
// is 0 when the file is exhausted.
func Read(dir, date string, offset, limit int) ([]Entry, int, error) {
	if len(date) != 10 || date[4] != '-' || date[7] != '-' {
		return nil, 0, ErrBadDate
	}
	t, err := time.Parse("2006-01-02", date)
	if err != nil {
		return nil, 0, ErrBadDate
	}
	path := filepath.Join(dir, fmt.Sprintf("aps-%s.log", t.Format("20060102")))
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, 0, ErrNoFile
		}
		return nil, 0, err
	}
	if offset < 0 {
		offset = 0
	}
	if limit < 1 || limit > 1000 {
		limit = 200
	}
	lines := strings.Split(strings.TrimRight(string(raw), "\n"), "\n")
	if offset >= len(lines) {
		return []Entry{}, 0, nil
	}
	entries := make([]Entry, 0, limit)
	last := offset
	for i := offset; i < len(lines) && len(entries) < limit; i++ {
		last = i
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		var e Entry
		if err := json.Unmarshal([]byte(line), &e); err != nil {
			continue // malformed line — skip, never fail the whole read
		}
		entries = append(entries, e)
	}
	next := 0
	if last+1 < len(lines) {
		next = last + 1
	}
	return entries, next, nil
}

func parseNameDate(name string) (time.Time, bool) {
	m := fileNameRe.FindStringSubmatch(name)
	if m == nil {
		return time.Time{}, false
	}
	t, err := time.ParseInLocation("20060102", m[1]+m[2]+m[3], time.Local)
	if err != nil {
		return time.Time{}, false
	}
	return t, true
}

func dailyName(t time.Time) string { return "aps-" + t.Format("20060102") + ".log" }
