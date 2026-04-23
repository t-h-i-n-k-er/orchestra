with open("agent/src/syscalls.rs", "rb") as f:
    b = f.read()

# Replace actual null bytes with the string "\0"
s = b.decode("utf-8", errors="ignore").replace("\x00", "\\0")

# And remove the "Fallback" completely just bubble up the error directly
s = s.replace("""    match read_export_dir(base, func_name) {
        Ok(target) => {
            cache_lock.lock().unwrap().insert(func_name.to_string(), (target.ssn, target.gadget_addr));
            Ok(target)
        }
        Err(e) => {
            // Fallback
            Err(e)
        }
    }""", """    let target = read_export_dir(base, func_name)?;
    cache_lock.lock().unwrap().insert(func_name.to_string(), (target.ssn, target.gadget_addr));
    Ok(target)""")

# Also let's change expect to a hard exit if map fails
s = s.replace(""".expect("Failed to map clean ntdll.dll")""", """.unwrap_or_else(|e| {
        tracing::error!("Fatal: Could not map clean ntdll.dll: {e}");
        std::process::exit(1);
    })""")

with open("agent/src/syscalls.rs", "w", encoding="utf-8") as f:
    f.write(s)
