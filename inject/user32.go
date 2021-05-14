package inject

import "syscall"

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
