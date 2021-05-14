package inject

var (
	TH32CS_SNAPPROCESS  uint32 = 0x00000002
	TH32CS_SNAPTHREAD   uint32 = 0x00000004
	THREAD_ALL_ACCESS   uint32 = 0xffff
	ERROR_NO_MORE_FILES string = "There are no more files."
	SUCCESS             string = "The operation completed successfully."
)

type HOOKPROC func(int, uintptr, uintptr) uintptr

type HANDLER func() uintptr

type baseRelocEntry uint16

func (b baseRelocEntry) Type() uint16 {
	return uint16(uint16(b) >> 12)
}

func (b baseRelocEntry) Offset() uint32 {
	return uint32(uint16(b) & 0x0FFF)
}
