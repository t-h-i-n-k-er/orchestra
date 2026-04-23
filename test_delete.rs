use std::os::windows::fs::OpenOptionsExt;
use std::os::windows::io::AsRawHandle;
use std::fs::OpenOptions;

fn main() {
    let _f = OpenOptions::new()
        .write(true)
        .create(true)
        .custom_flags(0x04000000) // FILE_FLAG_DELETE_ON_CLOSE
        .open("test.dll").unwrap();
}
