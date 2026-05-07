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
            let base = $crate::pe_resolve::get_module_handle_by_hash($dll_hash)?;
            let addr = $crate::pe_resolve::get_proc_address_by_hash(
                base,
                $crate::pe_resolve::hash_str(concat!($fn_name, "\0").as_bytes()),
            )?;
            Some(std::mem::transmute::<usize, $ty>(addr))
        });
        fn_ptr
    };
}
