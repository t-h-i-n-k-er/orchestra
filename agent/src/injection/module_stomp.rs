use anyhow::Result;
use crate::injection::Injector;

pub struct ModuleStompInjector;

impl Injector for ModuleStompInjector {
    fn inject(&self, pid: u32, payload: &[u8]) -> Result<()> {
        // Find legitimate loadable DLL not in use (e.g. version.dll)
        // Force load (remote LoadLibraryA via remote thread)
        // Walk PEB -> LDR to find base
        // NtWriteVirtualMemory over DLL .text
        // Call new entry
        log::info!("Attempting Module Stomping on pid: {}", pid);
        Ok(())
    }
}
