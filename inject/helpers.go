package inject

import (
	"fmt"
	"math/rand"
	"os"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

const errSuccess string = "The operation completed successfully."

func SelectRandomElement(array []uint32) int {
	randomIndex := rand.Intn(len(array))
	chosen := array[randomIndex]
	return int(chosen)
}

func Get64BitProcesses() []uint32 {
	fmt.Printf("\n[+] Listing running processes")

	processes, cbNeeded := EnumProcesses()

	var candidates []uint32
	for i := 0; i < int(cbNeeded); i++ {
		pid := processes[i]
		if pid == 0 && i > 0 {
			break
		} else if pid != uint32(os.Getpid()) {
			bitness := Is64Bit(pid)
			if bitness == 0 {
				candidates = append(candidates, pid)
			}
		}
	}
	fmt.Printf("\n[+] Number of process injection candidates: %d", len(candidates))
	return candidates
}

func Is64Bit(pid uint32) int {

	pHandle, err := OpenProcess(windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, 0, pid)

	if err.Error() == errSuccess {
		bitness := IsWow64Process(pHandle)
		CloseHandle(pHandle)
		return int(bitness)

	} else {
		CloseHandle(pHandle)
		return -1
	}
}

func StringToCharPtr(str string) *uint8 {
	chars := append([]byte(str), 0) // null terminated
	return &chars[0]
}

func StringToUTF16Ptr(str string) *uint16 {
	wchars := utf16.Encode([]rune(str + "\x00"))
	return &wchars[0]
}
