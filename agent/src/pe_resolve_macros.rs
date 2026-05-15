// ── Compile-time hash utilities ────────────────────────────────────────────
//
// These `const fn` helpers exactly mirror the runtime algorithms in
// `pe_resolve::hash_str` and `pe_resolve::hash_wstr` so that hash constants
// computed at compile time are guaranteed to match the values produced at
// runtime by the PEB-walking resolver.
//
// NOTE: They are **not** gated by `#[cfg(windows)]` so that downstream crates
// can compute hashes in const contexts on any host (including Linux build
// machines during cross-compilation).

/// Compile-time hash for ASCII API names. EXACTLY mirrors `pe_resolve::hash_str`.
pub const fn hash_str_const(s: &[u8]) -> u32 {
    let mut hash: u32 = pe_resolve::SEED;
    let mut i = 0;
    while i < s.len() {
        let b = s[i];
        if b == 0 {
            break;
        }
        hash = hash.rotate_right(13) ^ (b.to_ascii_lowercase() as u32);
        i += 1;
    }
    hash
}

/// Compile-time hash for wide (UTF-16) API names. EXACTLY mirrors `pe_resolve::hash_wstr`.
pub const fn hash_wstr_const(w: &[u16]) -> u32 {
    let mut hash: u32 = pe_resolve::SEED;
    let mut i = 0;
    while i < w.len() {
        let c = w[i];
        if c == 0 {
            break;
        }
        let lo = (c as u8).to_ascii_lowercase();
        let hi = ((c >> 8) as u8).to_ascii_lowercase();
        hash = hash.rotate_right(13) ^ (lo as u32);
        hash = hash.rotate_right(13) ^ (hi as u32);
        i += 1;
    }
    hash
}

/// Resolve a WinAPI function dynamically via PEB walking + API hashing.
///
/// Caches the resolved function pointer in a static `OnceLock` so that
/// repeated calls skip the PEB walk and hash lookup after the first
/// invocation.  Returns `Option<&$ty>` — `None` if the DLL or export
/// could not be found.
///
/// # Safety
///
/// The caller must ensure `$ty` is a valid function-pointer type and that
/// the DLL hash / function name correspond to a real export.  The resolved
/// address is only valid for the lifetime of the process (DLLs unloaded
/// after resolution will produce a dangling pointer — this is acceptable
/// for system DLLs like ntdll/kernel32 which are never unloaded).
///
/// # Example
///
/// ```ignore
/// let nt_close = resolve_api!(
///     NT_CLOSE,
///     pe_resolve::hash_str(b"ntdll.dll\0"),
///     "NtClose",
///     unsafe extern "system" fn(Handle) -> NTSTATUS
/// );
/// ```
#[cfg(windows)]
#[macro_export]
macro_rules! resolve_api {
    ($var:ident, $dll_hash:expr, $fn_name:literal, $ty:ty) => {
        static $var: std::sync::OnceLock<Option<$ty>> = std::sync::OnceLock::new();
        let fn_ptr = $var.get_or_init(|| unsafe {
            let base = match pe_resolve::get_module_handle_by_hash($dll_hash) {
                Some(b) => b,
                None => {
                    tracing::error!("resolve_api: module hash {:#x} not found", $dll_hash);
                    return None;
                }
            };
            let addr = match pe_resolve::get_proc_address_by_hash(
                base,
                pe_resolve::hash_str(concat!($fn_name, "\0").as_bytes()),
            ) {
                Some(a) => a,
                None => {
                    tracing::error!("resolve_api: {} not found", $fn_name);
                    return None;
                }
            };
            Some(std::mem::transmute::<usize, $ty>(addr))
        });
        fn_ptr
    };
}
