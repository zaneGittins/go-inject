/*
	Test with: https://gist.github.com/zaneGittins/c009620f26e5c1100aceb5de123dec65

	References
	- https://posts.specterops.io/adventures-in-dynamic-evasion-1fe0bac57aa
 	- https://github.com/Adepts-Of-0xCC/VBA-macro-experiments/blob/main/EDRHookDetector.vba
*/
package main

import (
	"fmt"
	"go-inject/inject"
	"time"
)

func main() {

	time.Sleep(5 * time.Second)

	fmt.Println("[+] Detecting hooks.")
	originalSyscall := 3100740428

	moduleHandle := inject.GetModuleHandleA("ntdll.dll")
	fmt.Printf("[+] Got module handle ntdll.dll %d\n", moduleHandle)

	address := inject.GetProcAddress(moduleHandle, "NtAllocateVirtualMemory")
	fmt.Printf("[+] Got process address of NtAllocateVirtualMemory %d\n", address)

	tmpCheck := inject.RtlMoveMemory(address, 4)
	fmt.Println("[+] Moved memory from address.")

	if int(tmpCheck) == originalSyscall {
		fmt.Printf("Not hooked! %d\n", tmpCheck)
	} else {
		fmt.Printf("Hooked! %d\n", tmpCheck)
	}
}
