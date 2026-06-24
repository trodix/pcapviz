//go:build windows

package observ

import (
	"os"
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

// processRSS returns this process's working set size (Windows equivalent of RSS).
func processRSS() uint64 {
	h := windows.CurrentProcess()
	return workingSet(h)
}

// childrenRSS sums the working set of all descendant processes (the WebView2
// render/GPU/network processes in desktop mode).
func childrenRSS() uint64 {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(snap)

	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snap, &pe); err != nil {
		return 0
	}
	children := map[uint32][]uint32{}
	for {
		children[pe.ParentProcessID] = append(children[pe.ParentProcessID], pe.ProcessID)
		if err := windows.Process32Next(snap, &pe); err != nil {
			break
		}
	}

	self := uint32(os.Getpid())
	var total uint64
	queue := append([]uint32{}, children[self]...)
	for len(queue) > 0 {
		pid := queue[0]
		queue = queue[1:]
		total += rssOfPid(pid)
		queue = append(queue, children[pid]...)
	}
	return total
}

func rssOfPid(pid uint32) uint64 {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return 0
	}
	defer windows.CloseHandle(h)
	return workingSet(h)
}

func workingSet(h windows.Handle) uint64 {
	var c processMemoryCounters
	c.cb = uint32(unsafe.Sizeof(c))
	r, _, _ := procGetProcessMemoryInfo.Call(
		uintptr(h),
		uintptr(unsafe.Pointer(&c)),
		uintptr(c.cb),
	)
	if r == 0 {
		return 0
	}
	return uint64(c.workingSetSize)
}
