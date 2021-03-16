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
	rtlMoveMemory = ntdll.NewProc("RtlMoveMemory")

	// KERNEL32
	createThread             = kernel32.NewProc("CreateThread")
	virtualAlloc             = kernel32.NewProc("VirtualAlloc")
	heapCreate               = kernel32.NewProc("HeapCreate")
	heapAlloc                = kernel32.NewProc("HeapAlloc")
	openProcess              = kernel32.NewProc("OpenProcess")
	virtualAllocEx           = kernel32.NewProc("VirtualAllocEx")
	virtualProtect           = kernel32.NewProc("VirtualProtect")
	writeProcessMemory       = kernel32.NewProc("WriteProcessMemory")
	createRemoteThread       = kernel32.NewProc("CreateRemoteThread")
	closeHandle              = kernel32.NewProc("CloseHandle")
	isWow64Process           = kernel32.NewProc("IsWow64Process")
	waitForSingleObject      = kernel32.NewProc("WaitForSingleObject")
	getProcAddress           = kernel32.NewProc("GetProcAddress")
	getModuleHandleA         = kernel32.NewProc("GetModuleHandleA")
	createToolhelp32Snapshot = kernel32.NewProc("CreateToolhelp32Snapshot")
	process32First           = kernel32.NewProc("Process32First")
	process32Next            = kernel32.NewProc("Process32Next")
	thread32First            = kernel32.NewProc("Thread32First")
	thread32Next             = kernel32.NewProc("Thread32Next")
	openThread               = kernel32.NewProc("OpenThread")
	queueUserAPC             = kernel32.NewProc("QueueUserAPC")

	// PSAPI
	enumProcesses = psapi.NewProc("EnumProcesses")
)
