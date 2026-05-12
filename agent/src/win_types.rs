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
    pub data1: DWORD,
    pub data2: USHORT,
    pub data3: USHORT,
    pub data4: [UCHAR; 8],
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
    pub length: USHORT,
    pub maximum_length: USHORT,
    pub buffer: PWSTR,
}

pub type PUNICODE_STRING = *mut UNICODE_STRING;

// ── Object attributes (NT-native) ──────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
pub struct OBJECT_ATTRIBUTES {
    pub length: ULONG,
    pub root_directory: HANDLE,
    pub object_name: PUNICODE_STRING,
    pub attributes: ULONG,
    pub security_descriptor: PVOID,
    pub security_quality_of_service: PVOID,
}

impl Default for OBJECT_ATTRIBUTES {
    fn default() -> Self {
        Self {
            length: std::mem::size_of::<Self>() as ULONG,
            root_directory: std::ptr::null_mut(),
            object_name: std::ptr::null_mut(),
            attributes: 0,
            security_descriptor: std::ptr::null_mut(),
            security_quality_of_service: std::ptr::null_mut(),
        }
    }
}

// ── IO status block (NT-native) ─────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct IO_STATUS_BLOCK {
    pub status: i32,
    pub information: usize,
}

// ── Process / thread structures ─────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct PROCESS_INFORMATION {
    pub h_process: HANDLE,
    pub h_thread: HANDLE,
    pub dw_process_id: DWORD,
    pub dw_thread_id: DWORD,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct STARTUPINFOW {
    pub cb: DWORD,
    pub lp_reserved: PWSTR,
    pub lp_desktop: PWSTR,
    pub lp_title: PWSTR,
    pub dw_x: DWORD,
    pub dw_y: DWORD,
    pub dw_x_size: DWORD,
    pub dw_y_size: DWORD,
    pub dw_x_count_chars: DWORD,
    pub dw_y_count_chars: DWORD,
    pub dw_fill_attribute: DWORD,
    pub dw_flags: DWORD,
    pub w_show_window: USHORT,
    pub cb_reserved2: USHORT,
    pub lp_reserved2: *mut UCHAR,
    pub h_std_input: HANDLE,
    pub h_std_output: HANDLE,
    pub h_std_error: HANDLE,
}

impl Default for STARTUPINFOW {
    fn default() -> Self {
        Self {
            cb: std::mem::size_of::<Self>() as DWORD,
            lp_reserved: std::ptr::null_mut(),
            lp_desktop: std::ptr::null_mut(),
            lp_title: std::ptr::null_mut(),
            dw_x: 0,
            dw_y: 0,
            dw_x_size: 0,
            dw_y_size: 0,
            dw_x_count_chars: 0,
            dw_y_count_chars: 0,
            dw_fill_attribute: 0,
            dw_flags: 0,
            w_show_window: 0,
            cb_reserved2: 0,
            lp_reserved2: std::ptr::null_mut(),
            h_std_input: std::ptr::null_mut(),
            h_std_output: std::ptr::null_mut(),
            h_std_error: std::ptr::null_mut(),
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
    pub w_param: WPARAM,
    pub l_param: LPARAM,
    pub time: DWORD,
    pub pt: POINT,
}

pub type UINT = u32;
pub type c_int = i32;

// ── Monitor info ────────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
pub struct MONITORINFO {
    pub cb_size: DWORD,
    pub rc_monitor: RECT,
    pub rc_work: RECT,
    pub dw_flags: DWORD,
}

impl Default for MONITORINFO {
    fn default() -> Self {
        Self {
            cb_size: std::mem::size_of::<Self>() as DWORD,
            rc_monitor: RECT::default(),
            rc_work: RECT::default(),
            dw_flags: 0,
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
    pub bi_size: DWORD,
    pub bi_width: LONG,
    pub bi_height: LONG,
    pub bi_planes: USHORT,
    pub bi_bit_count: USHORT,
    pub bi_compression: DWORD,
    pub bi_size_image: DWORD,
    pub bi_x_pels_per_meter: LONG,
    pub bi_y_pels_per_meter: LONG,
    pub bi_clr_used: DWORD,
    pub bi_clr_important: DWORD,
}

impl Default for BITMAPINFOHEADER {
    fn default() -> Self {
        Self {
            bi_size: std::mem::size_of::<Self>() as DWORD,
            bi_width: 0,
            bi_height: 0,
            bi_planes: 1,
            bi_bit_count: 0,
            bi_compression: BI_RGB,
            bi_size_image: 0,
            bi_x_pels_per_meter: 0,
            bi_y_pels_per_meter: 0,
            bi_clr_used: 0,
            bi_clr_important: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct RGBQUAD {
    pub rgb_blue: UCHAR,
    pub rgb_green: UCHAR,
    pub rgb_red: UCHAR,
    pub rgb_reserved: UCHAR,
}

impl Default for RGBQUAD {
    fn default() -> Self {
        Self {
            rgb_blue: 0,
            rgb_green: 0,
            rgb_red: 0,
            rgb_reserved: 0,
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct BITMAPINFO {
    pub bmi_header: BITMAPINFOHEADER,
    pub bmi_colors: [RGBQUAD; 1],
}

impl Default for BITMAPINFO {
    fn default() -> Self {
        Self {
            bmi_header: BITMAPINFOHEADER::default(),
            bmi_colors: [RGBQUAD::default(); 1],
        }
    }
}

// ── Keyboard hook ───────────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct KBDLLHOOKSTRUCT {
    pub vk_code: DWORD,
    pub scan_code: DWORD,
    pub flags: DWORD,
    pub time: DWORD,
    pub dw_extra_info: usize,
}

// ── Security attributes ─────────────────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
pub struct SECURITY_ATTRIBUTES {
    pub n_length: DWORD,
    pub lp_security_descriptor: LPVOID,
    pub b_inherit_handle: BOOL,
}

impl Default for SECURITY_ATTRIBUTES {
    fn default() -> Self {
        Self {
            n_length: std::mem::size_of::<Self>() as DWORD,
            lp_security_descriptor: std::ptr::null_mut(),
            b_inherit_handle: 0,
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

#[repr(C)]
#[derive(Clone, Copy)]
pub struct CONTEXT {
    pub p1_home: u64,
    pub p2_home: u64,
    pub p3_home: u64,
    pub p4_home: u64,
    pub p5_home: u64,
    pub p6_home: u64,
    pub context_flags: DWORD,
    pub mxcsr: DWORD,
    pub seg_cs: USHORT,
    pub seg_ds: USHORT,
    pub seg_es: USHORT,
    pub seg_fs: USHORT,
    pub seg_gs: USHORT,
    pub seg_ss: USHORT,
    pub e_flags: DWORD,
    pub dr0: u64,
    pub dr1: u64,
    pub dr2: u64,
    pub dr3: u64,
    pub dr6: u64,
    pub dr7: u64,
    pub rax: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rbx: u64,
    pub rsp: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    pub rip: u64,
    pub flt_save: [u8; 512],
    pub vector_register: [u128; 26],
    pub vector_control: u64,
    pub debug_control: u64,
    pub last_branch_to_rip: u64,
    pub last_branch_from_rip: u64,
    pub last_exception_to_rip: u64,
    pub last_exception_from_rip: u64,
}

impl Default for CONTEXT {
    fn default() -> Self {
        Self {
            p1_home: 0,
            p2_home: 0,
            p3_home: 0,
            p4_home: 0,
            p5_home: 0,
            p6_home: 0,
            context_flags: 0,
            mxcsr: 0,
            seg_cs: 0,
            seg_ds: 0,
            seg_es: 0,
            seg_fs: 0,
            seg_gs: 0,
            seg_ss: 0,
            e_flags: 0,
            dr0: 0,
            dr1: 0,
            dr2: 0,
            dr3: 0,
            dr6: 0,
            dr7: 0,
            rax: 0,
            rcx: 0,
            rdx: 0,
            rbx: 0,
            rsp: 0,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            flt_save: [0u8; 512],
            vector_register: [0u128; 26],
            vector_control: 0,
            debug_control: 0,
            last_branch_to_rip: 0,
            last_branch_from_rip: 0,
            last_exception_to_rip: 0,
            last_exception_from_rip: 0,
        }
    }
}

// ── COM helpers ─────────────────────────────────────────────────────────────

/// IUnknown vtable (minimal — only the three IUnknown methods).
#[repr(C)]
pub struct IUnknownVtbl {
    pub query_interface: unsafe extern "system" fn(
        *mut std::ffi::c_void,
        REFIID,
        *mut *mut std::ffi::c_void,
    ) -> HRESULT,
    pub add_ref: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
    pub release: unsafe extern "system" fn(*mut std::ffi::c_void) -> u32,
}

#[repr(C)]
pub struct IUnknown {
    pub lpvtbl: *const IUnknownVtbl,
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
