use anyhow::Result;
use module_loader::Plugin;

struct HelloPlugin;

impl Plugin for HelloPlugin {
    fn init(&self) -> Result<()> {
        // No-op for this simple plugin
        Ok(())
    }

    fn execute(&self, args: &str) -> Result<String> {
        Ok(format!("Hello, {}", args))
    }
}

// SAFETY: The plugin loader and `_create_plugin` symbol use a `*mut dyn Plugin`
// fat pointer convention by agreement; both sides are compiled by the same
// rustc and ABI-compatible. The `improper_ctypes_definitions` warning is
// therefore intentional and suppressed.
#[no_mangle]
#[allow(improper_ctypes_definitions)]
pub extern "C" fn _create_plugin() -> *mut dyn Plugin {
    Box::into_raw(Box::new(HelloPlugin))
}
