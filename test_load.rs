use std::os::windows::fs::OpenOptionsExt;
use std::fs::OpenOptions;
use std::io::Write;
use winapi::um::libloaderapi::LoadLibraryA;

fn main() {
    println!("Creating file");
    let mut opts = OpenOptions::new();
    opts.write(true).create(true).read(true);
    opts.custom_flags(0x04000000); // FILE_FLAG_DELETE_ON_CLOSE
    opts.share_mode(0x00000001 | 0x00000004); // FILE_SHARE_READ | FILE_SHARE_DELETE

    if let Ok(mut f) = opts.open("test_del.dll") {
        f.write_all(b"MZ").unwrap();
        // LoadLibrary
        let h = unsafe { LoadLibraryA(b"test_del.dll\0".as_ptr() as *const i8) };
        println!("Loaded: {:?}", h);
        std::mem::forget(f); // leak handle
    }
}
