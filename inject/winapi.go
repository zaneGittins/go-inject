package inject

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	TH32CS_SNAPPROCESS  uint32 = 0x00000002
	TH32CS_SNAPTHREAD   uint32 = 0x00000004
	THREAD_ALL_ACCESS   uint32 = 0xffff
	ERROR_NO_MORE_FILES string = "There are no more files."
	SUCCESS             string = "The operation completed successfully."
)

type HOOKPROC func(int, uintptr, uintptr) uintptr

type HANDLER func() uintptr

func RtlCopyMemory(destination uintptr, source []byte) {

	rtlCopyMemory.Call(destination, (uintptr)(unsafe.Pointer(&source[0])), uintptr(len(source)))
	return
}

func RtlMoveMemory(source uintptr, length int) int {

	var destination int
	rtlMoveMemory.Call((uintptr)(unsafe.Pointer(&destination)), source, uintptr(length))
	return destination
}

func RtlMoveMemory2(destination uintptr, source []byte) {

	rtlMoveMemory.Call(destination, (uintptr)(unsafe.Pointer(&source[0])), uintptr(len(source)))
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

func HeapAlloc(heap uintptr, dwFlags uint32, dwBytes int) uintptr {

	allocatedMemory, _, _ := heapAlloc.Call(heap, uintptr(dwFlags), uintptr(dwBytes))
	return allocatedMemory
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

func CreateToolhelp32Snapshot(flags uint32, pid uint32) uintptr {
	handle, _, _ := createToolhelp32Snapshot.Call(uintptr(flags), uintptr(pid))
	return handle
}

func Process32First(snapshot uintptr, processEntry *windows.ProcessEntry32) (uintptr, error) {

	result, _, err := process32First.Call(snapshot, (uintptr)(unsafe.Pointer(processEntry)))
	return result, err
}

func Process32Next(snapshot uintptr, processEntry *windows.ProcessEntry32) (uintptr, error) {

	result, _, err := process32Next.Call(snapshot, (uintptr)(unsafe.Pointer(processEntry)))
	return result, err
}

func Thread32First(snapshot uintptr, threadEntry *windows.ThreadEntry32) (uintptr, error) {

	result, _, err := thread32First.Call(snapshot, (uintptr)(unsafe.Pointer(threadEntry)))
	return result, err
}

func Thread32Next(snapshot uintptr, threadEntry *windows.ThreadEntry32) (uintptr, error) {

	result, _, err := thread32Next.Call(snapshot, (uintptr)(unsafe.Pointer(threadEntry)))
	return result, err
}

func OpenThread(desiredAccess uint32, inheritHandle uint32, threadId uint32) (uintptr, error) {

	tHandle, _, err := openThread.Call(uintptr(desiredAccess), uintptr(inheritHandle), uintptr(threadId))
	return tHandle, err
}

func QueueUserAPC(pfnAPC *uintptr, tHandle uintptr) uint32 {
	result, _, _ := queueUserAPC.Call((uintptr)(unsafe.Pointer(&pfnAPC)), tHandle, 0)
	return uint32(result)
}

func UUIDFromStringA(uuidString string, uuid uintptr) (uintptr, error) {
	status, _, err := uuidFromStringA.Call(uintptr(unsafe.Pointer(StringToCharPtr(uuidString))), uuid)
	return status, err
}

func EnumSystemLocalesA(lpLocaleEnumProc uintptr, dwFlags uint32) error {
	_, _, err := enumSystemLocalesA.Call(lpLocaleEnumProc, uintptr(dwFlags))
	return err
}

func GetCurrentThreadId() (uint32, error) {
	result, _, err := getCurrentThreadId.Call()
	return uint32(result), err
}

func SetConsoleCtrlHandler(handlerRoutine HANDLER, add uint32) error {

	_, _, err := setConsoleCtrlHandler.Call(uintptr(syscall.NewCallback(handlerRoutine)), uintptr(add))
	return err
}

func SetWindowsHookEx(idHook uint32, lpfn HOOKPROC, hmod uintptr, dwThreadID uint32) uintptr {

	result, _, _ := setWindowsHookExA.Call(
		uintptr(idHook),
		uintptr(syscall.NewCallback(lpfn)),
		uintptr(hmod),
		uintptr(dwThreadID),
	)
	return result
}

func GetMessage(lpMsg uintptr, hWnd uintptr, wMsgFilterMin uint32, wMsgFilterMax uint32) (uint32, error) {
	result, _, err := getMessageW.Call(lpMsg, hWnd, uintptr(wMsgFilterMin), uintptr(wMsgFilterMax))
	return uint32(result), err
}

func TranslateMessage(lpMsg uintptr) error {
	_, _, err := translateMessage.Call(lpMsg)
	return err
}

func DispatchMessage(lpMsg uintptr) error {
	_, _, err := dispatchMessage.Call(lpMsg)
	return err
}

func UnhookWindowsHookEx(hhk uintptr) error {
	_, _, err := unhookWindowsHookEx.Call(hhk)
	return err
}

func PostThreadMessage(idThread uint32, msg uint32, wparam uintptr, lparam uintptr) (uint32, error) {
	result, _, err := postThreadMessage.Call(uintptr(idThread), uintptr(msg), wparam, lparam)
	return uint32(result), err
}

func CallNextHookEx(hhook uintptr, nCode uint32, wparam uintptr, lparam uintptr) uintptr {
	result, _, _ := callNextHookEx.Call(hhook, uintptr(nCode), wparam, lparam)
	return result
}
