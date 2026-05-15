//! Runtime page-size resolution for injection modules.
//!
//! ARM64 Windows may use 4 KB **or** 16 KB pages depending on configuration.
//! Rather than hard-coding 0x1000, every injection module that needs page
//! alignment should call [`system_page_size`] (or the convenience wrapper
//! [`page_align`]).
//!
//! The implementation resolves `GetSystemInfo` via `pe_resolve` (no IAT
//! entry) and caches the result in a `OnceLock` so the syscall overhead is
//! paid at most once per process lifetime.

use std::sync::OnceLock;

/// Cached page size in bytes.
static PAGE_SIZE: OnceLock<usize> = OnceLock::new();

/// Return the system page size, querying it on first call.
///
/// Uses `GetSystemInfo` resolved via `pe_resolve` (no IAT entry).
/// Falls back to 4096 (standard 4 KB) if resolution fails.
fn query_page_size() -> usize {
    type FnGetSystemInfo = unsafe extern "system" fn(*mut u8); // SYSTEM_INFO*

    // SYSTEM_INFO layout (relevant fields):
    //   0..2   wProcessorArchitecture (WORD)
    //   2..4   wReserved (WORD)
    //   4..8   dwPageSize (DWORD)
    //   8..16  lpMinimumApplicationAddress (PVOID)
    //   16..24 lpMaximumApplicationAddress (PVOID)
    //   24..32 dwActiveProcessorMask (DWORD_PTR)
    // Total size: 48 bytes on 64-bit.
    #[repr(C)]
    #[derive(Default)]
    struct SystemInfo {
        w_processor_architecture: u16,
        _w_reserved: u16,
        dw_page_size: u32,
        _rest: [u64; 5], // enough padding for full struct
    }

    let fn_ptr: Option<FnGetSystemInfo> = (|| unsafe {
        let k32 = pe_resolve::get_module_handle_by_hash(pe_resolve::HASH_KERNEL32_DLL)?;
        let hash = pe_resolve::hash_str(b"GetSystemInfo\0");
        let addr = pe_resolve::get_proc_address_by_hash(k32, hash)?;
        Some(std::mem::transmute::<usize, FnGetSystemInfo>(addr))
    })();

    match fn_ptr {
        Some(get_system_info) => {
            let mut info: SystemInfo = unsafe { std::mem::zeroed() };
            unsafe { get_system_info(&mut info as *mut SystemInfo as *mut u8) };
            let sz = info.dw_page_size as usize;
            if sz > 0 && sz.is_power_of_two() {
                tracing::debug!("page_size: system page size = {} bytes", sz);
                sz
            } else {
                tracing::warn!(
                    "page_size: GetSystemInfo returned invalid page size {}, defaulting to 4096",
                    sz
                );
                4096
            }
        }
        None => {
            tracing::warn!("page_size: cannot resolve GetSystemInfo, defaulting to 4096 byte pages");
            4096
        }
    }
}

/// Return the system page size in bytes, caching the result on first call.
///
/// Guaranteed to be a power of two. Returns 4096 if the actual page size
/// cannot be determined.
pub fn system_page_size() -> usize {
    *PAGE_SIZE.get_or_init(query_page_size)
}

/// Align `size` up to the next page boundary using the runtime page size.
///
/// For a 4 KB page this is equivalent to `(size + 0xFFF) & !0xFFF`.
/// For a 16 KB page it becomes `(size + 0x3FFF) & !0x3FFF`.
pub fn page_align(size: usize) -> usize {
    let page = system_page_size();
    (size + page - 1) & !(page - 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_page_align_zero() {
        assert_eq!(page_align(0), 0);
    }

    #[test]
    fn test_page_align_one_byte() {
        let ps = system_page_size();
        assert_eq!(page_align(1), ps);
    }

    #[test]
    fn test_page_align_exact_page() {
        let ps = system_page_size();
        assert_eq!(page_align(ps), ps);
    }

    #[test]
    fn test_page_align_one_over() {
        let ps = system_page_size();
        assert_eq!(page_align(ps + 1), ps * 2);
    }

    #[test]
    fn test_system_page_size_is_power_of_two() {
        let ps = system_page_size();
        assert!(ps > 0);
        assert!(ps.is_power_of_two());
    }
}
