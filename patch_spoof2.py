with open("agent/src/syscalls.rs", "r") as f:
    text = f.read()

# Replace clean_call! definition
old_clean_call = """#[cfg(windows)]
#[macro_export]
macro_rules! clean_call {
    ($dll_name:expr, $func_name:expr, $fn_type:ty $(, $args:expr)* $(,)?) => {{
        let addr = $crate::syscalls::get_clean_api_addr($dll_name, $func_name)
            .unwrap_or_else(|e| {
                tracing::error!("Failed to resolve clean {}: {}", $func_name, e);
                std::process::exit(1);
            });
        let func: $fn_type = unsafe { std::mem::transmute(addr) };
        unsafe { func($($args),*) }
    }};
}"""

new_clean_call = """#[cfg(windows)]
#[macro_export]
macro_rules! clean_call {
    ($dll_name:expr, $func_name:expr, $fn_type:ty $(, $args:expr)* $(,)?) => {{
        let addr = $crate::syscalls::get_clean_api_addr($dll_name, $func_name)
            .unwrap_or_else(|e| {
                tracing::error!("Failed to resolve clean {}: {}", $func_name, e);
                std::process::exit(1);
            });
        // Gather arguments
        let args: &[u64] = &[$($args as u64),*];
        let arg1 = args.get(0).copied().unwrap_or(0);
        let arg2 = args.get(1).copied().unwrap_or(0);
        let arg3 = args.get(2).copied().unwrap_or(0);
        let arg4 = args.get(3).copied().unwrap_or(0);
        let stack_args = if args.len() > 4 { &args[4..] } else { &[] };
        
        let gadget = $crate::syscalls::find_jmp_rbx_gadget();
        if gadget == 0 {
            // fallback if no gadget found
            let func: $fn_type = unsafe { std::mem::transmute(addr) };
            unsafe { func($($args),*) }
        } else {
            let res = unsafe { $crate::syscalls::spoof_call(addr, gadget, arg1, arg2, arg3, arg4, stack_args) };
            // cast result back
            unsafe { std::mem::transmute_copy(&res) }
        }
    }};
}"""

text = text.replace(old_clean_call, new_clean_call)

with open("agent/src/syscalls.rs", "w") as f:
    f.write(text)
print("Replaced clean_call")
