with open("agent/src/syscalls.rs", "r") as f:
    orig = f.read()

spoof_fn_old = """#[cfg(windows)]
#[doc(hidden)]
#[inline(never)]
pub unsafe fn spoof_call(api_addr: usize, gadget_addr: usize, arg1: u64, arg2: u64, arg3: u64, arg4: u64, stack_args: &[u64]) -> u64 {
    let mut status: u64 = 0;
    let nstack = stack_args.len();
    let stack_ptr = stack_args.as_ptr();
    
    std::arch::asm!(
        // Save RBX and R14 since they are non-volatile and we use them
        "push rbx",
        "push r14",
        "push r15",
        
        // Save real return address logically by saving caller's state, but we need TLS...
        // Actually, the macro can just call spoof_call, and spoof_call manages the stack frame.
        // Wait, the prompt asked to use TLS. We will call set_spoof_ret from asm or before asm.
        // Let's just do it directly here using call set_spoof_ret if needed, or Rust wrapper:
        "mov rbx, 2f", // RBX = restore_stuff gadget
        
        // Calculate stack size to allocate
        "mov r14, rsp",
        "mov rax, {nstack}",
        "shl rax, 3",
        "add rax, 0x28 + 15",
        "and rax, -16",
        "sub rsp, rax",
        
        // Copy stack args
        "test {nstack}, {nstack}",
        "jz 1f",
        "mov rcx, {nstack}",
        "mov rsi, {stack_ptr}",
        "lea rdi, [rsp + 0x28]",
        "cld",
        "rep movsq",
        
        "1:",
        "mov rcx, {a1}",
        "mov rdx, {a2}",
        "mov r8, {a3}",
        "mov r9, {a4}",
        
        // Emulate call to API by pushing the gadget_addr (JMP RBX) as fake return address
        "mov r11, {api}",
        "mov r15, {gadget}",
        "push r15",
        "jmp r11", // Jump to API
        
        "2:", // After API returns to gadget, gadget does JMP RBX to here
        "mov rsp, r14", // Restore stack
        "mov {status_out}, rax",
        
        "pop r15",
        "pop r14",
        "pop rbx",
        api = in(reg) api_addr,
        gadget = in(reg) gadget_addr,
        nstack = in(reg) nstack,
        stack_ptr = in(reg) stack_ptr,
        a1 = in(reg) arg1,
        a2 = in(reg) arg2,
        a3 = in(reg) arg3,
        a4 = in(reg) arg4,
        status_out = out(reg) status,
        out("rcx") _, out("rdx") _, out("r8") _, out("r9") _, out("r10") _, out("r11") _, out("rax") _,
        out("rsi") _, out("rdi") _,
        options(att_syntax),
    );
    status
}"""

spoof_fn_new = """#[cfg(windows)]
#[doc(hidden)]
#[inline(never)]
pub unsafe fn spoof_call(api_addr: usize, gadget_addr: usize, arg1: u64, arg2: u64, arg3: u64, arg4: u64, stack_args: &[u64]) -> u64 {
    let mut status: u64 = 0;
    let nstack = stack_args.len();
    let stack_ptr = stack_args.as_ptr();
    
    // We will store our dummy return address via TLS
    let mut dummy_ret = 0usize;
    
    std::arch::asm!(
        "lea {dummy}, [rip + 2f]",
        dummy = out(reg) dummy_ret,
        options(nostack),
    );
    set_spoof_ret(dummy_ret);
    
    std::arch::asm!(
        "push rbx",
        "push r14",
        "push r15",
        
        "lea rbx, [rip + 3f]", // JMP RBX will land at 3:
        
        "mov r14, rsp",
        "mov rax, {nstack}",
        "shl rax, 3",
        "add rax, 0x28 + 15",
        "and rax, -16",
        "sub rsp, rax",
        
        "test {nstack}, {nstack}",
        "jz 1f",
        "mov rcx, {nstack}",
        "mov rsi, {stack_ptr}",
        "lea rdi, [rsp + 0x28]",
        "cld",
        "rep movsq",
        
        "1:",
        "mov rcx, {a1}",
        "mov rdx, {a2}",
        "mov r8, {a3}",
        "mov r9, {a4}",
        
        "mov r11, {api}",
        "mov r15, {gadget}",
        "push r15", // fake return address
        "jmp r11",
        
        // When gadget does JMP RBX, it lands here
        "3:",
        "mov rsp, r14", 
        "pop r15",
        "pop r14",
        "pop rbx",
        
        // Jump to TLS return address
        "jmp {real_ret}",
        
        "2:", // The real return address recorded in TLS
        "mov {status_out}, rax",
        
        api = in(reg) api_addr,
        gadget = in(reg) gadget_addr,
        nstack = in(reg) nstack,
        stack_ptr = in(reg) stack_ptr,
        a1 = in(reg) arg1,
        a2 = in(reg) arg2,
        a3 = in(reg) arg3,
        a4 = in(reg) arg4,
        real_ret = in(reg) get_spoof_ret(),
        status_out = out(reg) status,
        out("rcx") _, out("rdx") _, out("r8") _, out("r9") _, out("r10") _, out("r11") _, out("rax") _,
        out("rsi") _, out("rdi") _,
        options(att_syntax),
    );
    status
}"""

orig = orig.replace(spoof_fn_old, spoof_fn_new)
with open("agent/src/syscalls.rs", "w") as f:
    f.write(orig)

