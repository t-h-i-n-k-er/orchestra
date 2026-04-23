use winapi::shared::ntdef::{HANDLE, NTSTATUS, OBJECT_ATTRIBUTES, POBJECT_ATTRIBUTES, PLARGE_INTEGER, PVOID, ULONG};
use winapi::shared::basetsd::{SIZE_T, ULONG_PTR};
use winapi::um::winnt::{ACCESS_MASK, SECTION_MAP_READ, SECTION_MAP_EXECUTE, PAGE_EXECUTE_READ, SEC_IMAGE};
use winapi::um::libloaderapi::{GetModuleHandleA, GetProcAddress};
use winapi::um::fileapi::{CreateFileA, OPEN_EXISTING};
use winapi::um::winnt::{FILE_SHARE_READ, GENERIC_READ};
use winapi::um::errhandlingapi::GetLastError;
use winapi::um::handleapi::CloseHandle;

type NtCreateSectionFn = unsafe extern "system" fn(
    SectionHandle: *mut HANDLE,
    DesiredAccess: ACCESS_MASK,
    ObjectAttributes: POBJECT_ATTRIBUTES,
    MaximumSize: PLARGE_INTEGER,
    SectionPageProtection: ULONG,
    AllocationAttributes: ULONG,
    FileHandle: HANDLE,
) -> NTSTATUS;

type NtMapViewOfSectionFn = unsafe extern "system" fn(
    SectionHandle: HANDLE,
    ProcessHandle: HANDLE,
    BaseAddress: *mut PVOID,
    ZeroBits: ULONG_PTR,
    CommitSize: SIZE_T,
    SectionOffset: PLARGE_INTEGER,
    ViewSize: *mut SIZE_T,
    InheritDisposition: u32,
    AllocationType: ULONG,
    Win32Protect: ULONG,
) -> NTSTATUS;

fn test() {
    unsafe {
        let ntdll = GetModuleHandleA(b"ntdll.dll\0".as_ptr() as *const i8);
        assert!(!ntdll.is_null());
        let nt_create_section: NtCreateSectionFn = std::mem::transmute(GetProcAddress(ntdll, b"NtCreateSection\0".as_ptr() as *const i8));
        let nt_map_view_of_section: NtMapViewOfSectionFn = std::mem::transmute(GetProcAddress(ntdll, b"NtMapViewOfSection\0".as_ptr() as *const i8));
        
        let path = b"C:\\Windows\\System32\\ntdll.dll\0".as_ptr() as *const i8;
        let mut handle: HANDLE = CreateFileA(
            path,
            GENERIC_READ,
            FILE_SHARE_READ,
            std::ptr::null_mut(),
            OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        );
        assert!(handle != winapi::um::handleapi::INVALID_HANDLE_VALUE);
        
        let mut section: HANDLE = std::ptr::null_mut();
        let status = nt_create_section(
            &mut section,
            SECTION_MAP_READ | SECTION_MAP_EXECUTE,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
            PAGE_EXECUTE_READ,
            SEC_IMAGE,
            handle
        );
        CloseHandle(handle);
        assert!(status == 0, "NtCreateSection failed: {:x}", status);
        
        let mut base_addr: PVOID = std::ptr::null_mut();
        let mut view_size: SIZE_T = 0;
        let status = nt_map_view_of_section(
            section,
            -1isize as HANDLE, // CurrentProcess
            &mut base_addr,
            0,
            0,
            std::ptr::null_mut(),
            &mut view_size,
            1, // ViewShare
            0,
            PAGE_EXECUTE_READ,
        );
        CloseHandle(section);
        assert!(status == 0, "NtMapViewOfSection failed: {:x}", status);
        println!("Mapped ntdll at {:?}", base_addr);
    }
}
fn main() { test(); }
