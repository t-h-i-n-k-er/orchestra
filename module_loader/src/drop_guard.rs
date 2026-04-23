use winapi::um::memoryapi::VirtualFree;
use winapi::um::winnt::MEM_RELEASE;
use std::ffi::c_void;

pub struct VirtualAllocGuard {
    pub ptr: *mut c_void,
    pub active: bool,
}

impl Drop for VirtualAllocGuard {
    fn drop(&mut self) {
        if self.active && !self.ptr.is_null() {
            unsafe { VirtualFree(self.ptr, 0, MEM_RELEASE); }
        }
    }
}
