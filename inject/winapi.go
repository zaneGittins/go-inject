package inject

var (
	TH32CS_SNAPPROCESS uint32 = 0x00000002
	TH32CS_SNAPTHREAD  uint32 = 0x00000004
	THREAD_ALL_ACCESS  uint32 = 0xffff
	CONTEXT_FULL       uint32 = 0x400003
	CONTEXT_SEGMENTS   uint32 = 0x04
	CONTEXt_ALL        uint32 = 0xffffff
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

// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context
type XMM_SAVE_AREA32 struct {
	ControlWord    uint16
	StatusWord     uint16
	TagWord        byte
	Reserved1      byte
	ErrorOpcode    uint16
	ErrorOffset    uint32
	ErrorSelector  uint16
	Reserved2      uint16
	DataOffset     uint32
	DataSelector   uint16
	Reserved3      uint16
	MxCsr          uint32
	MxCsr_Mask     uint32
	FloatRegisters [8]M128A
	XmmRegisters   [256]byte
	Reserved4      [96]byte
}

// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context
type M128A struct {
	Low  uint64
	High int64
}

// https://docs.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-context
type CONTEXT struct {
	P1Home uint64
	P2Home uint64
	P3Home uint64
	P4Home uint64
	P5Home uint64
	P6Home uint64

	ContextFlags uint32
	MxCsr        uint32

	SegCs  uint16
	SegDs  uint16
	SegEs  uint16
	SegFs  uint16
	SegGs  uint16
	SegSs  uint16
	EFlags uint32

	Dr0 uint64
	Dr1 uint64
	Dr2 uint64
	Dr3 uint64
	Dr6 uint64
	Dr7 uint64

	Rax uint64
	Rcx uint64
	Rdx uint64
	Rbx uint64
	Rsp uint64
	Rbp uint64
	Rsi uint64
	Rdi uint64
	R8  uint64
	R9  uint64
	R10 uint64
	R11 uint64
	R12 uint64
	R13 uint64
	R14 uint64
	R15 uint64

	Rip uint64

	FltSave XMM_SAVE_AREA32

	VectorRegister [26]M128A
	VectorControl  uint64

	DebugControl         uint64
	LastBranchToRip      uint64
	LastBranchFromRip    uint64
	LastExceptionToRip   uint64
	LastExceptionFromRip uint64
}

type WOW64_CONTEXT struct {
	ContextFlags      uint32
	Dr0               uint32
	Dr1               uint32
	Dr2               uint32
	Dr3               uint32
	Dr6               uint32
	Dr7               uint32
	FloatSave         WOW64_FLOATING_SAVE_AREA
	SegGs             uint32
	SegFs             uint32
	SegEs             uint32
	SegDs             uint32
	Edi               uint32
	Esi               uint32
	Ebx               uint32
	Edx               uint32
	Ecx               uint32
	Eax               uint32
	Ebp               uint32
	Eip               uint32
	SegCs             uint32
	EFlags            uint32
	Esp               uint32
	SegSs             uint32
	ExtendedRegisters [512]byte
}

type WOW64_FLOATING_SAVE_AREA struct {
	ControlWord   uint32
	StatusWord    uint32
	TagWord       uint32
	ErrorOffset   uint32
	ErrorSelector uint32
	DataOffset    uint32
	DataSelector  uint32
	RegisterArea  [80]byte
	Cr0NpxState   uint32
}

type LDT_ENTRY struct {
	LimitLow uint16
	BaseLow  uint16
	HighWord struct {
		Bytes struct {
			BaseMid byte
			Flags1  byte
			Flags2  byte
			BaseHi  byte
		}
		Bits struct {
			BaseMid     uint32
			Type        uint32
			Dpl         uint32
			Pres        uint32
			LimitHi     uint32
			Sys         uint32
			Reserved0   uint32
			DefaultBig  uint32
			Granularity uint32
			BaseHi      uint32
		}
	}
}

type PROCESS_BASIC_INFORMATION struct {
	Reserved1       uint64
	PebBaseAddress  uint64
	Reserved2       uint64
	Reserved3       uint64
	UniqueProcessId uint64
	Reserved4       uint64
}
