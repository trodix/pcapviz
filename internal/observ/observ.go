// Package observ provides pcapviz's observability: an in-memory, ring-buffered
// slog logger consultable from the application itself (no log file is written
// at startup — nothing pollutes the disk), plus crash reports persisted only
// when an actual crash happens.
//
// Logs are kept in a bounded circular buffer and also mirrored to stderr. The
// level is dynamic: debug records are not even stored until debug mode is turned
// on (at runtime, from the UI), so leaving debug off costs nothing.
package observ

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

// Version is the build version, included in crash reports. Override with
// -ldflags "-X pcapviz/internal/observ.Version=...".
var Version = "dev"

// Entry is one captured log record, as exposed to the UI.
type Entry struct {
	Time    time.Time      `json:"time"`
	Level   string         `json:"level"`
	Message string         `json:"message"`
	Attrs   map[string]any `json:"attrs,omitempty"`

	lvl slog.Level // for filtering; not serialized
}

// recorder is the thread-safe ring buffer of entries.
type recorder struct {
	mu      sync.RWMutex
	entries []Entry
	max     int
}

func (r *recorder) add(e Entry) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, e)
	if len(r.entries) > r.max {
		n := copy(r.entries, r.entries[len(r.entries)-r.max:])
		r.entries = r.entries[:n]
	}
}

// snapshot returns entries at or above min, keeping at most limit most-recent
// ones, in chronological order.
func (r *recorder) snapshot(min slog.Level, limit int) []Entry {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Entry, 0, len(r.entries))
	for _, e := range r.entries {
		if e.lvl >= min {
			out = append(out, e)
		}
	}
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out
}

// Logger is the central observability handle: a slog.Logger backed by the ring
// buffer (and stderr), with dynamic level control and crash reporting.
type Logger struct {
	rec   *recorder
	level *slog.LevelVar
	sl    *slog.Logger
}

// New builds a Logger keeping up to max entries. debug selects the initial
// level (debug when true, info otherwise).
func New(max int, debug bool) *Logger {
	if max <= 0 {
		max = 2000
	}
	lv := &slog.LevelVar{}
	rec := &recorder{max: max}
	l := &Logger{rec: rec, level: lv}
	l.SetDebug(debug)

	bufH := &bufferHandler{rec: rec, level: lv}
	stderrH := slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: lv})
	l.sl = slog.New(fanout{bufH, stderrH})
	return l
}

// Slog returns the underlying *slog.Logger to pass around.
func (l *Logger) Slog() *slog.Logger { return l.sl }

// SetDebug toggles debug-level capture at runtime.
func (l *Logger) SetDebug(on bool) {
	if on {
		l.level.Set(slog.LevelDebug)
	} else {
		l.level.Set(slog.LevelInfo)
	}
}

// Debug reports whether debug capture is currently on.
func (l *Logger) Debug() bool { return l.level.Level() <= slog.LevelDebug }

// Level returns the current minimum captured level as a lowercase string.
func (l *Logger) Level() string { return strings.ToLower(l.level.Level().String()) }

// Entries returns captured records at or above minLevel (e.g. "warn"), most
// recent limit kept. An unknown level defaults to info.
func (l *Logger) Entries(minLevel string, limit int) []Entry {
	min, err := ParseLevel(minLevel)
	if err != nil {
		min = slog.LevelInfo
	}
	return l.rec.snapshot(min, limit)
}

// ParseLevel maps a level name to a slog.Level.
func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return slog.LevelDebug, nil
	case "", "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error", "err":
		return slog.LevelError, nil
	}
	return 0, fmt.Errorf("unknown log level %q", s)
}

// --- slog handlers ---

// bufferHandler writes records into the ring buffer, gated by the dynamic level.
type bufferHandler struct {
	rec   *recorder
	level *slog.LevelVar
	attrs []slog.Attr
	group string
}

func (h *bufferHandler) Enabled(_ context.Context, l slog.Level) bool {
	return l >= h.level.Level()
}

func (h *bufferHandler) Handle(_ context.Context, r slog.Record) error {
	e := Entry{Time: r.Time, Level: r.Level.String(), Message: r.Message, lvl: r.Level}
	attrs := map[string]any{}
	for _, a := range h.attrs {
		attrs[a.Key] = a.Value.Any()
	}
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.Any()
		return true
	})
	if len(attrs) > 0 {
		e.Attrs = attrs
	}
	h.rec.add(e)
	return nil
}

func (h *bufferHandler) WithAttrs(as []slog.Attr) slog.Handler {
	nh := *h
	nh.attrs = append(append([]slog.Attr{}, h.attrs...), as...)
	return &nh
}

func (h *bufferHandler) WithGroup(name string) slog.Handler {
	nh := *h
	nh.group = name
	return &nh
}

// fanout dispatches each record to several handlers.
type fanout []slog.Handler

func (f fanout) Enabled(ctx context.Context, l slog.Level) bool {
	for _, h := range f {
		if h.Enabled(ctx, l) {
			return true
		}
	}
	return false
}

func (f fanout) Handle(ctx context.Context, r slog.Record) error {
	for _, h := range f {
		if h.Enabled(ctx, r.Level) {
			_ = h.Handle(ctx, r)
		}
	}
	return nil
}

func (f fanout) WithAttrs(as []slog.Attr) slog.Handler {
	out := make(fanout, len(f))
	for i, h := range f {
		out[i] = h.WithAttrs(as)
	}
	return out
}

func (f fanout) WithGroup(name string) slog.Handler {
	out := make(fanout, len(f))
	for i, h := range f {
		out[i] = h.WithGroup(name)
	}
	return out
}
