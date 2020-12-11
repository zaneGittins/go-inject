package inject

import (
	"golang.org/x/sys/windows"
)

var (
	ntdll    = windows.NewLazySystemDLL("ntdll.dll")
	kernel32 = windows.NewLazySystemDLL("kernel32.dll")
	psapi    = windows.NewLazySystemDLL("psapi.dll")

	// NTDLL
	rtlCopyMemory = ntdll.NewProc("RtlCopyMemory")

	// KERNEL32
	createThread        = kernel32.NewProc("CreateThread")
	virtualAlloc        = kernel32.NewProc("VirtualAlloc")
	heapCreate          = kernel32.NewProc("HeapCreate")
	heapAlloc           = kernel32.NewProc("HeapAlloc")
	openProcess         = kernel32.NewProc("OpenProcess")
	virtualAllocEx      = kernel32.NewProc("VirtualAllocEx")
	virtualProtect      = kernel32.NewProc("VirtualProtect")
	writeProcessMemory  = kernel32.NewProc("WriteProcessMemory")
	createRemoteThread  = kernel32.NewProc("CreateRemoteThread")
	closeHandle         = kernel32.NewProc("CloseHandle")
	isWow64Process      = kernel32.NewProc("IsWow64Process")
	waitForSingleObject = kernel32.NewProc("WaitForSingleObject")

	// PSAPI
	enumProcesses = psapi.NewProc("EnumProcesses")
)
