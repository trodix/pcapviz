//go:build windows

package observ

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// processMemoryCounters mirrors the Win32 PROCESS_MEMORY_COUNTERS struct.
type processMemoryCounters struct {
	cb                         uint32
	pageFaultCount             uint32
	peakWorkingSetSize         uintptr
	workingSetSize             uintptr
	quotaPeakPagedPoolUsage    uintptr
	quotaPagedPoolUsage        uintptr
	quotaPeakNonPagedPoolUsage uintptr
	quotaNonPagedPoolUsage     uintptr
	pagefileUsage              uintptr
	peakPagefileUsage          uintptr
}

var (
	psapi                    = windows.NewLazySystemDLL("psapi.dll")
	procGetProcessMemoryInfo = psapi.NewProc("GetProcessMemoryInfo")
)

// processRSS returns the working set size (the Windows equivalent of RSS).
func processRSS() uint64 {
	var c processMemoryCounters
	c.cb = uint32(unsafe.Sizeof(c))
	r, _, _ := procGetProcessMemoryInfo.Call(
		uintptr(windows.CurrentProcess()),
		uintptr(unsafe.Pointer(&c)),
		uintptr(c.cb),
	)
	if r == 0 {
		return 0
	}
	return uint64(c.workingSetSize)
}
