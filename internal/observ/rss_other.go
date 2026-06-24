//go:build !linux && !windows

package observ

// processRSS is unavailable on this platform; callers fall back to runtime.Sys.
func processRSS() uint64 { return 0 }
