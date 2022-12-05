package main

import (
	"fmt"
	"go-inject/inject"

	"golang.org/x/sys/windows"
)

func main() {

	processHandle, _ := inject.OpenProcess((0xFFFF), 0, windows.GetCurrentProcessId())

	pbi, _ := inject.NtQueryInformationProcess(processHandle)
	fmt.Printf("PEB:%d\n", pbi.PebBaseAddress)

	pebSize := 128
	peb := make([]byte, pebSize)

	inject.ReadProcessMemory(processHandle, uintptr(pbi.PebBaseAddress), peb, uint32(len(peb)))

	fmt.Printf("Read %v\n", peb)

	if peb[2] == 1 {
		fmt.Println("BeingDebugged")
	} else {
		fmt.Println("No debugger detected.")
	}

	windows.SleepEx(5000, false)
}
