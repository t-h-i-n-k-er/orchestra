#![allow(non_snake_case)]
//! Local Windows type definitions.
//!
//! Replaces winapi type-only imports with local `#[repr(C)]` definitions.
//! These are **type-only** — they do not produce IAT entries.  However,
//! removing the winapi import eliminates any chance of the linker pulling
//! in a DLL reference through a type definition and keeps the binary
//! self-contained.

// ── Primitive type aliases ─────────────────────────────────────────────────

pub type BOOL = i32;
pub type DWORD = u32;
pub type LONG = i32;
pub type ULONG = u32;
pub type USHORT = u16;
pub type UCHAR = u8;
pub type SIZE_T = usize;
pub type LPARAM = isize;
pub type WPARAM = usize;
pub type LRESULT = isize;
pub type HRESULT = i32;
pub type HANDLE = *mut std::ffi::c_void;
pub type HWND = *mut std::ffi::c_void;
pub type HMODULE = *mut std::ffi::c_void;
pub type HINSTANCE = *mut std::ffi::c_void;
pub type HBITMAP = *mut std::ffi::c_void;
pub type HDC = *mut std::ffi::c_void;
pub type HMONITOR = *mut std::ffi::c_void;
pub type PVOID = *mut std::ffi::c_void;
pub type LPVOID = *mut std::ffi::c_void;
pub type LPCVOID = *const std::ffi::c_void;
pub type PWSTR = *mut u16;
pub type PCWSTR = *const u16;
pub type PSTR = *mut i8;
pub type PCSTR = *const i8;
pub type BSTR = *mut u16;
pub type REFIID = *const GUID;
pub type CLSID = GUID;
pub type LPDWORD = *mut u32;
pub type LPCWSTR = *const u16; // alias for PCWSTR
pub type LPWSTR = *mut u16; // alias for PWSTR
pub type NTSTATUS = i32;

pub const TRUE: BOOL = 1;
pub const FALSE: BOOL = 0;

/// Pseudohandle for the current process (GetCurrentProcess() returns this).
pub const CURRENT_PROCESS: HANDLE = -1isize as *mut std::ffi::c_void;

/// Pseudohandle for the current thread (GetCurrentThread() returns this).
pub const CURRENT_THREAD: HANDLE = -2isize as *mut std::ffi::c_void;

// ── HRESULT helpers ─────────────────────────────────────────────────────────

pub const S_OK: HRESULT = 0;
pub const E_FAIL: HRESULT = 0x80004005_u32 as i32;

#[inline]
pub const fn succeeded(hr: HRESULT) -> bool {
    hr >= 0
}

#[inline]
pub const fn failed(hr: HRESULT) -> bool {
    hr < 0
}

// ── Simple structs ──────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FILETIME {
    pub dw_low_date_time: DWORD,
    pub dw_high_date_time: DWORD,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct POINT {
    pub x: LONG,
    pub y: LONG,
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct RECT {
    pub left: LONG,
    pub top: LONG,
    pub right: LONG,
    pub bottom: LONG,
}

pub type LPRECT = *mut RECT;

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct GUID {
    pub Data1: DWORD,
    pub Data2: USHORT,
    pub Data3: USHORT,
    pub Data4: [UCHAR; 8],
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SIZE {
    pub cx: LONG,
    pub cy: LONG,
}

// ── Unicode string (NT-native) ──────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct UNICODE_STRING {
    pub Length: USHORT,
    pub MaximumLength: USHORT,
    pub Buffer: PWSTR,
}

pub type PUNICODE_STRING = *mut UNICODE_STRING;

// ── Object attributes (NT-native) ──────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OBJECT_ATTRIBUTES {
    pub Length: ULONG,
    pub RootDirectory: HANDLE,
    pub ObjectName: PUNICODE_STRING,
    pub Attributes: ULONG,
    pub SecurityDescriptor: PVOID,
    pub SecurityQualityOfService: PVOID,
}

impl Default for OBJECT_ATTRIBUTES {
    fn default() -> Self {
        Self {
            Length: std::mem::size_of::<Self>() as ULONG,
            RootDirectory: std::ptr::null_mut(),
            ObjectName: std::ptr::null_mut(),
            Attributes: 0,
            SecurityDescriptor: std::ptr::null_mut(),
            SecurityQualityOfService: std::ptr::null_mut(),
        }
    }
}

// ── IO status block (NT-native) ─────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IO_STATUS_BLOCK {
    pub Status: i32,
    pub Information: usize,
}

// ── Process / thread structures ─────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PROCESS_INFORMATION {
    pub hProcess: HANDLE,
    pub hThread: HANDLE,
    pub dwProcessId: DWORD,
    pub dwThreadId: DWORD,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct STARTUPINFOW {
    pub cb: DWORD,
    pub lpReserved: PWSTR,
    pub lpDesktop: PWSTR,
    pub lpTitle: PWSTR,
    pub dwX: DWORD,
    pub dwY: DWORD,
    pub dwXSize: DWORD,
    pub dwYSize: DWORD,
    pub dwXCountChars: DWORD,
    pub dwYCountChars: DWORD,
    pub dwFillAttribute: DWORD,
    pub dwFlags: DWORD,
    pub wShowWindow: USHORT,
    pub cbReserved2: USHORT,
    pub lpReserved2: *mut UCHAR,
    pub hStdInput: HANDLE,
    pub hStdOutput: HANDLE,
    pub hStdError: HANDLE,
}

impl Default for STARTUPINFOW {
    fn default() -> Self {
        Self {
            cb: std::mem::size_of::<Self>() as DWORD,
            lpReserved: std::ptr::null_mut(),
            lpDesktop: std::ptr::null_mut(),
            lpTitle: std::ptr::null_mut(),
            dwX: 0,
            dwY: 0,
            dwXSize: 0,
            dwYSize: 0,
            dwXCountChars: 0,
            dwYCountChars: 0,
            dwFillAttribute: 0,
            dwFlags: 0,
            wShowWindow: 0,
            cbReserved2: 0,
            lpReserved2: std::ptr::null_mut(),
            hStdInput: std::ptr::null_mut(),
            hStdOutput: std::ptr::null_mut(),
            hStdError: std::ptr::null_mut(),
        }
    }
}

// ── System time ─────────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct SYSTEMTIME {
    pub w_year: USHORT,
    pub w_month: USHORT,
    pub w_day_of_week: USHORT,
    pub w_day: USHORT,
    pub w_hour: USHORT,
    pub w_minute: USHORT,
    pub w_second: USHORT,
    pub w_milliseconds: USHORT,
}

// ── Window message ──────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct MSG {
    pub hwnd: HWND,
    pub message: UINT,
    pub wParam: WPARAM,
    pub lParam: LPARAM,
    pub time: DWORD,
    pub pt: POINT,
}

pub type UINT = u32;
pub type c_int = i32;

// ── Monitor info ────────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MONITORINFO {
    pub cbSize: DWORD,
    pub rcMonitor: RECT,
    pub rcWork: RECT,
    pub dwFlags: DWORD,
}

impl Default for MONITORINFO {
    fn default() -> Self {
        Self {
            cbSize: std::mem::size_of::<Self>() as DWORD,
            rcMonitor: RECT::default(),
            rcWork: RECT::default(),
            dwFlags: 0,
        }
    }
}

// ── Bitmap / GDI structures ─────────────────────────────────────────────────

/// DIB color table identifier.
pub const DIB_RGB_COLORS: UINT = 0;

/// Raster operation code for BitBlt — copy source rectangle directly to
/// destination rectangle.
pub const SRCCOPY: DWORD = 0x00CC0020;

/// Bi-compression type: uncompressed RGB.
pub const BI_RGB: DWORD = 0;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BITMAPINFOHEADER {
    pub biSize: DWORD,
    pub biWidth: LONG,
    pub biHeight: LONG,
    pub biPlanes: USHORT,
    pub biBitCount: USHORT,
    pub biCompression: DWORD,
    pub biSizeImage: DWORD,
    pub biXPelsPerMeter: LONG,
    pub biYPelsPerMeter: LONG,
    pub biClrUsed: DWORD,
    pub biClrImportant: DWORD,
}

impl Default for BITMAPINFOHEADER {
    fn default() -> Self {
        Self {
            biSize: std::mem::size_of::<Self>() as DWORD,
            biWidth: 0,
            biHeight: 0,
            biPlanes: 1,
            biBitCount: 0,
            biCompression: BI_RGB,
            biSizeImage: 0,
            biXPelsPerMeter: 0,
            biYPelsPerMeter: 0,
            biClrUsed: 0,
            biClrImportant: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RGBQUAD {
    pub rgbBlue: UCHAR,
    pub rgbGreen: UCHAR,
    pub rgbRed: UCHAR,
    pub rgbReserved: UCHAR,
}

impl Default for RGBQUAD {
    fn default() -> Self {
        Self {
            rgbBlue: 0,
            rgbGreen: 0,
            rgbRed: 0,
            rgbReserved: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BITMAPINFO {
    pub bmiHeader: BITMAPINFOHEADER,
    pub bmiColors: [RGBQUAD; 1],
}

impl Default for BITMAPINFO {
    fn default() -> Self {
        Self {
            bmiHeader: BITMAPINFOHEADER::default(),
            bmiColors: [RGBQUAD::default(); 1],
        }
    }
}

// ── Keyboard hook ───────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct KBDLLHOOKSTRUCT {
    pub vkCode: DWORD,
    pub scanCode: DWORD,
    pub flags: DWORD,
    pub time: DWORD,
    pub dwExtraInfo: usize,
}

// ── Security attributes ─────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SECURITY_ATTRIBUTES {
    pub nLength: DWORD,
    pub lpSecurityDescriptor: LPVOID,
    pub bInheritHandle: BOOL,
}

impl Default for SECURITY_ATTRIBUTES {
    fn default() -> Self {
        Self {
            nLength: std::mem::size_of::<Self>() as DWORD,
            lpSecurityDescriptor: std::ptr::null_mut(),
            bInheritHandle: 0,
        }
    }
}

// ── CONTEXT (x86_64) ───────────────────────────────────────────────────────
//
// Minimal definition matching the Windows x86_64 CONTEXT structure.
// Only the register fields needed for Get/SetThreadContext are defined.
// The full structure is 928 bytes on Windows x86_64.

pub const CONTEXT_INTEGER: DWORD = 0x00000002;
pub const CONTEXT_CONTROL: DWORD = 0x00000001;
pub const CONTEXT_FULL: DWORD = CONTEXT_CONTROL | CONTEXT_INTEGER | 0x00000004;
pub const CONTEXT_DEBUG_REGISTERS: DWORD = 0x00100000;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CONTEXT {
    pub P1Home: u64,
    pub P2Home: u64,
    pub P3Home: u64,
    pub P4Home: u64,
    pub P5Home: u64,
    pub P6Home: u64,
    pub ContextFlags: DWORD,
    pub MxCsr: DWORD,
    pub SegCs: USHORT,
    pub SegDs: USHORT,
    pub SegEs: USHORT,
    pub SegFs: USHORT,
    pub SegGs: USHORT,
    pub SegSs: USHORT,
    pub EFlags: DWORD,
    pub Dr0: u64,
    pub Dr1: u64,
    pub Dr2: u64,
    pub Dr3: u64,
    pub Dr6: u64,
    pub Dr7: u64,
    pub Rax: u64,
    pub Rcx: u64,
    pub Rdx: u64,
    pub Rbx: u64,
    pub Rsp: u64,
    pub Rbp: u64,
    pub Rsi: u64,
    pub Rdi: u64,
    pub R8: u64,
    pub R9: u64,
    pub R10: u64,
    pub R11: u64,
    pub R12: u64,
    pub R13: u64,
    pub R14: u64,
    pub R15: u64,
    pub Rip: u64,
    pub FltSave: [u8; 512],
    pub VectorRegister: [u128; 26],
    pub VectorControl: u64,
    pub DebugControl: u64,
    pub LastBranchToRip: u64,
    pub LastBranchFromRip: u64,
    pub LastExceptionToRip: u64,
    pub LastExceptionFromRip: u64,
}

impl Default for CONTEXT {
    fn default() -> Self {
        Self {
            P1Home: 0,
            P2Home: 0,
            P3Home: 0,
            P4Home: 0,
            P5Home: 0,
            P6Home: 0,
            ContextFlags: 0,
            MxCsr: 0,
            SegCs: 0,
            SegDs: 0,
            SegEs: 0,
            SegFs: 0,
            SegGs: 0,
            SegSs: 0,
            EFlags: 0,
            Dr0: 0,
            Dr1: 0,
            Dr2: 0,
            Dr3: 0,
            Dr6: 0,
            Dr7: 0,
            Rax: 0,
            Rcx: 0,
            Rdx: 0,
            Rbx: 0,
            Rsp: 0,
            Rbp: 0,
            Rsi: 0,
            Rdi: 0,
            R8: 0,
            R9: 0,
            R10: 0,
            R11: 0,
            R12: 0,
            R13: 0,
            R14: 0,
            R15: 0,
            Rip: 0,
            FltSave: [0u8; 512],
            VectorRegister: [0u128; 26],
            VectorControl: 0,
            DebugControl: 0,
            LastBranchToRip: 0,
            LastBranchFromRip: 0,
            LastExceptionToRip: 0,
            LastExceptionFromRip: 0,
        }
    }
}

// ── COM helpers ─────────────────────────────────────────────────────────────

/// IUnknown vtable (minimal — only the three IUnknown methods).
#[repr(C)]
pub struct IUnknownVtbl {
    pub QueryInterface: unsafe extern "system" fn(
        *mut std::ffi::c_void,
        REFIID,
        *mut *mut std::ffi::c_void,
    ) -> HRESULT,
    pub AddRef: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
    pub Release: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
}

#[repr(C)]
pub struct IUnknown {
    pub lpVtbl: *const IUnknownVtbl,
}

// ── VARIANT (simplified) ───────────────────────────────────────────────────
//
// The full VARIANT is a large discriminated union.  We only need it as an
// opaque block of memory that we pass to COM methods (always initialized
// via `std::mem::zeroed()` before use).  The layout matches the 24-byte
// Windows VARIANT on x86_64.

#[repr(C)]
#[derive(Clone, Copy)]
pub struct VARIANT {
    _data: [u64; 3],
}

impl Default for VARIANT {
    fn default() -> Self {
        Self { _data: [0; 3] }
    }
}

// ── Network adapter ─────────────────────────────────────────────────────────

/// Maximum adapter address length (MAC = 6 bytes, padded to 8).
pub const MAX_ADAPTER_ADDRESS_LENGTH: usize = 8;

/// Simplified IP_ADAPTER_ADDRESSES — only the fields we access
/// (PhysicalAddress, PhysicalAddressLength, Next).
///
/// Layout matches the Windows IP_ADAPTER_ADDRESSES_LH struct up to the
/// fields we need.  The full struct has many more fields after PhysicalAddress,
/// but we only read PhysicalAddress, PhysicalAddressLength, and Next.
#[repr(C)]
pub struct IP_ADAPTER_ADDRESSES {
    _union: u64,                             // u (Alignment / Length+IfIndex)
    pub next: *mut IP_ADAPTER_ADDRESSES,     // Next
    _adapter_name: PSTR,                     // AdapterName
    _first_unicast: *mut std::ffi::c_void,   // FirstUnicastAddress
    _first_anycast: *mut std::ffi::c_void,   // FirstAnycastAddress
    _first_multicast: *mut std::ffi::c_void, // FirstMulticastAddress
    _first_dns: *mut std::ffi::c_void,       // FirstDnsServerAddress
    _dns_suffix: PWSTR,                      // DnsSuffix
    _description: PWSTR,                     // Description
    _friendly_name: PWSTR,                   // FriendlyName
    pub physical_address: [UCHAR; MAX_ADAPTER_ADDRESS_LENGTH], // PhysicalAddress
    pub physical_address_length: ULONG,      // PhysicalAddressLength
}

/// Windows `PROCESSENTRY32W` structure for `CreateToolhelp32Snapshot`.
///
/// Used to enumerate all processes in a Toolhelp32 snapshot when walking the
/// parent process chain for sandbox lineage detection.
#[repr(C)]
pub struct ProcessEntry32W {
    pub dw_size: u32,
    pub cnt_usage: u32,
    pub th32_process_id: u32,
    pub th32_default_heap_id: usize, // ULONG_PTR — pointer-sized
    pub th32_module_id: u32,
    pub cnt_threads: u32,
    pub th32_parent_process_id: u32,
    pub pc_pri_class_base: i32,
    pub dw_flags: u32,
    pub sz_exe_file: [u16; 260], // MAX_PATH wide chars
}

impl Default for ProcessEntry32W {
    fn default() -> Self {
        Self {
            dw_size: 0,
            cnt_usage: 0,
            th32_process_id: 0,
            th32_default_heap_id: 0,
            th32_module_id: 0,
            cnt_threads: 0,
            th32_parent_process_id: 0,
            pc_pri_class_base: 0,
            dw_flags: 0,
            sz_exe_file: [0u16; 260],
        }
    }
}

// ── Handle constants ────────────────────────────────────────────────────────

pub const INVALID_HANDLE_VALUE: HANDLE = -1isize as *mut std::ffi::c_void;

// ── Memory protection constants ─────────────────────────────────────────────

pub const PAGE_READWRITE: DWORD = 0x04;
pub const PAGE_EXECUTE_READWRITE: DWORD = 0x40;
pub const PAGE_NOACCESS: DWORD = 0x01;
