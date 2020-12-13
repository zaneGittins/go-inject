package inject

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func RtlCopyMemory(destination uintptr, source []byte) {

	rtlCopyMemory.Call(destination, (uintptr)(unsafe.Pointer(&source[0])), uintptr(len(source)))
	return
}

func RtlMoveMemory(source uintptr, length int) int {

	var destination int
	rtlMoveMemory.Call((uintptr)(unsafe.Pointer(&destination)), source, uintptr(length))
	return destination
}

func CreateThread(startAddress uintptr) uintptr {

	thread, _, _ := createThread.Call(0, 0, startAddress, uintptr(0), 0, 0)
	return thread
}

func VirtualAlloc(address uintptr, size int, allocationType uint64, protect uint64) uintptr {

	addr, _, _ := virtualAlloc.Call(address, uintptr(size), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	return addr
}

func HeapCreate(options uint32, initialSize int, maximumSize uint32) uintptr {

	heap, _, _ := heapCreate.Call(uintptr(options), uintptr(initialSize), uintptr(maximumSize))
	return heap
}

func HeapAlloc(heap uintptr, dwFlags uint32, dwBytes int) {

	heapAlloc.Call(heap, uintptr(dwFlags), uintptr(dwBytes))
	return
}

func OpenProcess(desiredAccess uint32, inheritHandle uint32, processId uint32) (uintptr, error) {

	pHandle, _, err := openProcess.Call(uintptr(desiredAccess), uintptr(inheritHandle), uintptr(processId))
	return pHandle, err

}

func VirtualAllocEx(process uintptr, address uintptr, length int, allocationType uint32, protect uint32) uintptr {

	memptr, _, _ := virtualAllocEx.Call(process, uintptr(address), uintptr(length), uintptr(allocationType), uintptr(protect))
	return memptr
}

func WriteProcessMemory(process uintptr, baseAddress uintptr, buffer []byte) uint32 {

	var nbytes uint32
	writeProcessMemory.Call(uintptr(process), baseAddress, (uintptr)(unsafe.Pointer(&buffer[0])), uintptr(len(buffer)), uintptr(nbytes))
	return nbytes
}

func CreateRemoteThread(process uintptr, threadAttributes uintptr, stackSize uint64, startAddress uintptr, paramater uintptr, creationFlags uint32, threadID uint32) {

	createRemoteThread.Call(uintptr(process), threadAttributes, uintptr(stackSize), startAddress, uintptr(paramater), uintptr(creationFlags), uintptr(threadID))
	return
}

func CloseHandle(handle uintptr) {

	closeHandle.Call(handle)
	return
}

func IsWow64Process(handle uintptr) uint32 {
	var bitness uint32
	isWow64Process.Call(handle, uintptr(unsafe.Pointer(&bitness)))
	return bitness
}

func EnumProcesses() ([1024]uint32, uint32) {
	var processes [1024]uint32
	var cbNeeded uint32
	enumProcesses.Call((uintptr)(unsafe.Pointer(&processes)), uintptr(len(processes)), (uintptr)(unsafe.Pointer(&cbNeeded)))
	return processes, cbNeeded
}

func VirtualProtect(address uintptr, size int, newProtect uint32) uint32 {

	var oldProtect uint32
	virtualProtect.Call(address, uintptr(size), uintptr(newProtect), (uintptr)(unsafe.Pointer(&oldProtect)))
	return oldProtect
}

func WaitForSingleObject(thread uintptr, milliseconds uint32) {

	waitForSingleObject.Call(uintptr(windows.Handle(thread)), uintptr(milliseconds))
	return
}

func GetProcAddress(module uintptr, procName string) uintptr {

	address, _, _ := getProcAddress.Call(module, uintptr(unsafe.Pointer(StringToCharPtr(procName))))
	return address
}

func GetModuleHandleA(moduleName string) uintptr {

	handle, _, _ := getModuleHandleA.Call(uintptr(unsafe.Pointer(StringToCharPtr(moduleName))))
	return handle
}
