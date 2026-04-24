#[cfg(windows)]
pub mod thread_hijack;
#[cfg(windows)]
pub mod module_stomp;

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
