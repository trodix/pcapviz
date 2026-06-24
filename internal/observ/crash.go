package observ

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"
)

// CrashInfo describes a persisted crash report file.
type CrashInfo struct {
	Name string    `json:"name"`
	Time time.Time `json:"time"`
	Size int64     `json:"size"`
}

// crashDir is where crash reports are written: the user's cache dir (falling
// back to the temp dir), never the working directory.
func crashDir() string {
	d, err := os.UserCacheDir()
	if err != nil {
		d = os.TempDir()
	}
	return filepath.Join(d, "pcapviz", "crashes")
}

// WriteCrashReport persists a crash report (panic value, stack and the recent
// in-memory logs) and returns its path. It is only ever called when an actual
// crash occurs, so no file exists unless something went wrong.
func (l *Logger) WriteCrashReport(recovered any, stack []byte) (string, error) {
	dir := crashDir()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, "crash-"+time.Now().Format("20060102-150405")+".log")

	var b strings.Builder
	fmt.Fprintf(&b, "pcapviz crash report\n")
	fmt.Fprintf(&b, "Time:    %s\n", time.Now().Format(time.RFC3339))
	fmt.Fprintf(&b, "Version: %s\n", Version)
	fmt.Fprintf(&b, "Runtime: %s %s/%s\n\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	fmt.Fprintf(&b, "Panic: %v\n\n", recovered)
	fmt.Fprintf(&b, "Stack:\n%s\n", stack)
	fmt.Fprintf(&b, "Recent logs:\n")
	for _, e := range l.rec.snapshot(0, 300) {
		fmt.Fprintf(&b, "%s [%s] %s", e.Time.Format(time.RFC3339), e.Level, e.Message)
		if len(e.Attrs) > 0 {
			fmt.Fprintf(&b, " %v", e.Attrs)
		}
		b.WriteByte('\n')
	}

	if err := os.WriteFile(path, []byte(b.String()), 0o644); err != nil {
		return "", err
	}
	return path, nil
}

// CrashReports lists persisted crash reports, most recent first.
func (l *Logger) CrashReports() ([]CrashInfo, error) {
	dir := crashDir()
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []CrashInfo
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "crash-") {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		out = append(out, CrashInfo{Name: e.Name(), Time: info.ModTime(), Size: info.Size()})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	return out, nil
}

// ReadCrash returns the contents of a crash report by file name. The name is
// sanitized to its base, so it cannot escape the crash directory.
func (l *Logger) ReadCrash(name string) ([]byte, error) {
	name = filepath.Base(name)
	if !strings.HasPrefix(name, "crash-") {
		return nil, fmt.Errorf("not a crash report: %q", name)
	}
	return os.ReadFile(filepath.Join(crashDir(), name))
}
