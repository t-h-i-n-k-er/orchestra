use winapi::um::winnt;
fn main() {
    let size = std::mem::size_of::<winapi::um::winnt::IMAGE_IMPORT_DESCRIPTOR>();
    println!("IID size: {}", size);
}
