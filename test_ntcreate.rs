fn main() {}
#[cfg(windows)]
extern "system" {
    fn NtCreateThreadEx(
        ThreadHandle: *mut *mut std::ffi::c_void,
        DesiredAccess: u32,
        ObjectAttributes: *mut std::ffi::c_void,
        ProcessHandle: *mut std::ffi::c_void,
        StartRoutine: *mut std::ffi::c_void,
        Argument: *mut std::ffi::c_void,
        CreateFlags: u32,
        ZeroBits: usize,
        StackSize: usize,
        MaximumStackSize: usize,
        AttributeList: *mut std::ffi::c_void,
    ) -> i32;
}
