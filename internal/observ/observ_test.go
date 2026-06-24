package observ

import (
	"os"
	"strings"
	"testing"
)

func TestBufferLevelsAndDebugToggle(t *testing.T) {
	l := New(50, false)

	l.Slog().Debug("d1")
	l.Slog().Info("i1")
	l.Slog().Warn("w1")
	l.Slog().Error("e1")

	// debug off => the debug record is dropped, not stored.
	if got := len(l.Entries("debug", 0)); got != 3 {
		t.Fatalf("entries (debug off) = %d, want 3", got)
	}
	if got := len(l.Entries("warn", 0)); got != 2 {
		t.Errorf("warn+ entries = %d, want 2", got)
	}
	if got := len(l.Entries("error", 0)); got != 1 {
		t.Errorf("error entries = %d, want 1", got)
	}

	// Enable debug at runtime; new debug records are now captured.
	l.SetDebug(true)
	if !l.Debug() {
		t.Fatal("Debug() = false after SetDebug(true)")
	}
	l.Slog().Debug("d2")
	if got := len(l.Entries("debug", 0)); got != 4 {
		t.Errorf("entries (debug on) = %d, want 4", got)
	}
}

func TestRingBufferCap(t *testing.T) {
	l := New(5, false)
	for i := 0; i < 20; i++ {
		l.Slog().Info("msg")
	}
	if got := len(l.Entries("info", 0)); got != 5 {
		t.Errorf("kept %d entries, want cap 5", got)
	}
}

func TestCrashReport(t *testing.T) {
	t.Setenv("XDG_CACHE_HOME", t.TempDir()) // keep crash files out of the real cache

	l := New(10, false)
	l.Slog().Error("boom", "code", 42)

	path, err := l.WriteCrashReport("test panic", []byte("goroutine stack trace"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"test panic", "goroutine stack trace", "boom", "code"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("crash report missing %q", want)
		}
	}

	reports, err := l.CrashReports()
	if err != nil || len(reports) != 1 {
		t.Fatalf("CrashReports = %v, %v", reports, err)
	}
	body, err := l.ReadCrash(reports[0].Name)
	if err != nil || !strings.Contains(string(body), "test panic") {
		t.Errorf("ReadCrash = %q, %v", body, err)
	}

	// Path traversal is rejected.
	if _, err := l.ReadCrash("../../etc/passwd"); err == nil {
		t.Error("ReadCrash allowed traversal")
	}
}
