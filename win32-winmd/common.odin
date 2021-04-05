package win32_winmd

import windows "core:sys/windows"
import win32 "core:sys/win32"
import c "core:c"
LARGE_INTEGER :: windows.LARGE_INTEGER;
ULARGE_INTEGER :: u64;
DWORD :: windows.DWORD;
LONG :: windows.LONG;
ULONG :: windows.ULONG;
BOOL :: windows.BOOL;
Guid :: windows.GUID;
intptr_t :: c.intptr_t;
size_t :: c.size_t;

SERVICETYPE :: ULONG;

WORD :: u16;
WPARAM :: win32.Wparam;
LPARAM :: win32.Lparam;
LRESULT :: win32.Lresult;
HRESULT :: win32.Hresult;
RECT :: win32.Rect;
HWND :: win32.Hwnd;
HANDLE :: win32.Handle;
HINSTANCE :: HANDLE;
Point :: win32.Point;
POINT :: Point;
LUID :: _LUID;
//HICON     :: distinct HANDLE;
//HCURSOR   :: distinct HANDLE;
//HBRUSH    :: distinct HANDLE;
//HMENU     :: distinct HANDLE;
//HBITMAP   :: distinct HANDLE;
//Hgdiobj   :: distinct Handle;

// GDI
//HDC :: win32.Handle;
//HMENU :: HANDLE;

SIZE :: struct {
	cx: u32,
	cy: u32,
}

_LUID :: struct {
		LowPart: DWORD,
		HighPart: LONG,
}

IUnknown :: struct {
	using vtbl: ^IUnknown_Vtbl,
}

IUnknown_Vtbl :: struct {
	QueryInterface : proc(this: ^IUnknown, riid: ^Guid, ppvObject: ^rawptr) -> HRESULT,
	AddRef : proc(this: ^IUnknown) -> u32,
	Release : proc(this: ^IUnknown) -> u32,
}

SECURITY_ATTRIBUTES :: struct {
		nLength: u32,
		lpSecurityDescriptor: rawptr,
		bInheritHandle: bool,
}
// Todo: check 

TrustLevel :: enum {
	BaseTrust,
	PartialTrust,
	FullTrust
}

WAVEFORMATEX :: struct {
    wFormatTag: WORD,        /* format type */
    nChannels: WORD,        /* number of channels (i.e. mono, stereo...) */
    nSamplesPerSec: DWORD,    /* sample rate */
    nAvgBytesPerSec: DWORD,   /* for buffer estimation */
    nBlockAlign: WORD,       /* block size of data */
    wBitsPerSample: WORD,    /* Number of bits per sample of mono data */
    cbSize: WORD,            /* The count in bytes of the size of
                                    extra information (after cbSize) */
}

POINTS :: struct {
	x: i16,
	y: i16
}

// BLENDFUNCTION :: struct {
// 	BlendOp: u8,
// 	BlendFlags: u8,
// 	SourceConstantAlpha: u8,
// 	AlphaFormat: u8
// }

RECTL :: struct {
	left: LONG,
	top: LONG,
	right: LONG,
	bottom: LONG
}

POINTL :: struct {
	x: LONG,
	y: LONG,
}

AUDIO_STREAM_CATEGORY :: enum {
	AudioCategory_Other = 0,
	AudioCategory_ForegroundOnlyMedia = 1,
	AudioCategory_Communications = 3,
	AudioCategory_Alerts = 4,
	AudioCategory_SoundEffects = 5,
	AudioCategory_GameEffects = 6,
	AudioCategory_GameMedia = 7,
	AudioCategory_GameChat = 8,
	AudioCategory_Speech = 9,
	AudioCategory_Movie = 10,
	AudioCategory_Media = 11
}

FILETIME :: struct {
    dwLowDateTime: DWORD,
    dwHighDateTime: DWORD
}

OVERLAPPED :: struct {
	Internal: ^ULONG,
	InternalHigh: ^ULONG,
	Offset: DWORD,
	OffsetHigh: DWORD,
	hEvent: HANDLE,
}

BLOB :: struct {
    cbSize: ULONG,
    pBlobData: ^u8
}


INTERNET_SCHEME :: enum {
    INTERNET_SCHEME_PARTIAL = -2,
    INTERNET_SCHEME_UNKNOWN = -1,
    INTERNET_SCHEME_DEFAULT = 0,
    INTERNET_SCHEME_FTP,
    INTERNET_SCHEME_GOPHER,
    INTERNET_SCHEME_HTTP,
    INTERNET_SCHEME_HTTPS,
    INTERNET_SCHEME_FILE,
    INTERNET_SCHEME_NEWS,
    INTERNET_SCHEME_MAILTO,
    INTERNET_SCHEME_SOCKS,
    INTERNET_SCHEME_JAVASCRIPT,
    INTERNET_SCHEME_VBSCRIPT,
    INTERNET_SCHEME_RES,
    INTERNET_SCHEME_FIRST = INTERNET_SCHEME_FTP,
    INTERNET_SCHEME_LAST = INTERNET_SCHEME_RES
}

SYSTEMTIME :: struct {
	year, month: u16,
	day_of_week, day: u16,
	hour, minute, second, millisecond: u16,
}

PROCESSOR_NUMBER :: struct {
    Group : u16,
    Number: u8,
    Reserved: u8
}

_flowspec :: struct {
    TokenRate: ULONG,            /* In Bytes/sec */
    TokenBucketSize: ULONG,        /* In Bytes */
    PeakBandwidth: ULONG,          /* In Bytes/sec */
    Latency: ULONG,                /* In microseconds */
    DelayVariation: ULONG,         /* In microseconds */
    ServiceType: SERVICETYPE,
    MaxSduSize: ULONG,             /* In Bytes */
    MinimumPolicedSize: ULONG     /* In Bytes */
}

DL_EUI48 :: DWORD; // WRONG!!
FARPROC :: proc "std" () -> i32;
PROC :: proc "std" () -> i32;
