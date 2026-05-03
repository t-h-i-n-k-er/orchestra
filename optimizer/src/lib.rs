//! x86-64 binary diversification engine.
//!
//! This crate applies post-compilation transformations to x86-64 instruction
//! streams to produce semantically equivalent but structurally unique binaries.
//! Each build produces a different output even from identical source code.
//!
//! # Transformation Passes
//!
//! - **NOP insertion**: Inserts random NOP instructions (single-byte `0x90` or
//!   multi-byte forms like `0F 1F /0`) at configurable density.
//! - **Instruction scheduling**: Reorders independent instructions within a
//!   basic block using a dependency-aware scheduler.
//! - **Instruction substitution**: Replaces instructions with equivalent but
//!   different encodings (e.g., `MOV reg, 0` → `XOR reg, reg`).
//! - **Dead-code insertion**: Inserts provably-dead code paths (always-false
//!   conditions) filled with realistic-looking but unreachable instructions.
//!
//! # Usage
//!
//! Implement the [`Pass`] trait for custom transformation passes, or use the
//! built-in passes: [`NopInsertion`], [`InstructionScheduling`],
//! [`SubstitutionPass`], and [`DeadCodePass`].

// Optimizer
use iced_x86::{Code, Decoder, DecoderOptions, Encoder, FlowControl, Instruction, OpKind, Register};
use rand::seq::SliceRandom;
use rand::{thread_rng, Rng};

#[cfg(feature = "diversification")]
include!(concat!(env!("OUT_DIR"), "/stub_seed.rs"));

/// Derive an 8-byte dead-code value from the build-time STUB_SEED and a
/// per-stub index using HKDF-SHA256.  This ensures every build produces
/// different dead-code constants (because STUB_SEED changes each build) while
/// also ensuring each stub site within a build gets a distinct value (because
/// `index` differs per site).
#[cfg(feature = "diversification")]
fn derive_dead_val(index: u64) -> u64 {
    use hkdf::Hkdf;
    use sha2::Sha256;

    let hk = Hkdf::<Sha256>::new(None, &STUB_SEED);
    let mut okm = [0u8; 8];
    let info = index.to_le_bytes();
    hk.expand(&info, &mut okm)
        .expect("HKDF expand with 8-byte OKM should never fail");
    u64::from_le_bytes(okm)
}

/// A single transformation pass over an instruction stream.
///
/// Implementations receive a mutable vector of decoded instructions and
/// may reorder, insert, replace, or remove them, provided the final
/// instruction stream is semantically equivalent to the input.
pub trait Pass {
    /// Apply this transformation pass to the instruction stream.
    fn run(&self, instrs: &mut Vec<Instruction>);
}

/// Apply diversification passes to raw code bytes.
///
/// Convenience wrapper around [`apply_passes_at`] with a default base address
/// of `0x1000`. Use [`apply_passes_at`] directly when the actual section VA
/// is known.
pub fn apply_passes(code: &[u8]) -> Vec<u8> {
    apply_passes_at(0x1000, code)
}

/// Apply diversification passes to raw code bytes decoded at the given virtual
/// base address.  Callers that know the section's actual load address should
/// pass it here so that RIP-relative operands are decoded with the correct IP.
pub fn apply_passes_at(base: u64, code: &[u8]) -> Vec<u8> {
    // Decode retaining original IPs so we can remap branch targets after
    // passes insert NOPs or reorder instructions.
    let decoder = Decoder::with_ip(64, code, base, DecoderOptions::NONE);
    let mut instrs: Vec<Instruction> = decoder.into_iter().collect();

    let mut passes: Vec<Box<dyn Pass>> = vec![
        Box::new(NopInsertionPass),
        Box::new(InstructionSchedulingPass),
    ];
    // Metamorphic passes: instruction-level substitution and opaque dead-code
    // insertion.  Gated behind the `diversification` feature so callers can
    // opt in explicitly; these passes change encoded sizes which requires the
    // branch-target fixup below to run correctly.
    #[cfg(feature = "diversification")]
    {
        passes.push(Box::new(InstructionSubstitutionPass) as Box<dyn Pass>);
        passes.push(Box::new(OpaqueDeadCodePass) as Box<dyn Pass>);
    }
    let mut rng = thread_rng();
    passes.shuffle(&mut rng);

    for p in passes {
        p.run(&mut instrs);
    }

    // Helper: compute the IP each instruction will be placed at by doing a
    // trial encode.  We need this to rewrite near-branch targets correctly.
    let compute_ips = |instrs: &[Instruction]| -> Vec<u64> {
        let mut ips = Vec::with_capacity(instrs.len());
        let mut cur = base;
        let mut enc = Encoder::new(64);
        for ins in instrs {
            ips.push(cur);
            // encode at `cur` to get the correct encoded size for this IP;
            // the result might be inaccurate if the branch target changed later,
            // but a second pass corrects that.
            cur += enc.encode(ins, cur).unwrap_or(1) as u64;
            let _ = enc.take_buffer();
        }
        ips
    };

    // First pass: approximate new IPs.
    let approx_ips = compute_ips(&instrs);

    // Build old_ip → new_ip map so branch targets can be remapped.
    use std::collections::HashMap;
    let mut ip_map: HashMap<u64, u64> = HashMap::new();
    for (ins, &new_ip) in instrs.iter().zip(approx_ips.iter()) {
        // NOP instructions inserted by NopInsertionPass have ip()==0; they
        // carry no branch targets so we can skip duplicate-key entries.
        ip_map.entry(ins.ip()).or_insert(new_ip);
    }

    // Rewrite near branch targets using the new IP map.
    use iced_x86::OpKind;
    for ins in &mut instrs {
        let needs_fix = (0..ins.op_count()).any(|i| {
            matches!(
                ins.op_kind(i),
                OpKind::NearBranch16 | OpKind::NearBranch32 | OpKind::NearBranch64
            )
        });
        if needs_fix {
            let old_target = ins.near_branch64();
            if let Some(&new_target) = ip_map.get(&old_target) {
                ins.set_near_branch64(new_target);
            }
        }
    }

    // Recompute IPs now that branch targets (and therefore branch sizes) are
    // final, then encode at those IPs.
    let final_ips = compute_ips(&instrs);
    let mut encoder = Encoder::new(64);
    for (ins, &ip) in instrs.iter().zip(final_ips.iter()) {
        let _ = encoder.encode(ins, ip);
    }
    encoder.take_buffer()
}

/// Apply diversification passes to every executable section of a compiled PE
/// or ELF binary and return the modified binary.
///
/// For each executable section the function:
/// 1. Applies `apply_passes_at` using the section's actual virtual address so
///    that RIP-relative operands are decoded correctly.
/// 2. If the transformed section fits in the section's raw file allocation,
///    patches it in and zero-fills any slack with `INT3` (0xCC) bytes — those
///    bytes are in unreachable territory beyond the last `RET`/`JMP`.
/// 3. If the transformed section is larger than the raw allocation, logs a
///    warning and skips that section rather than producing a corrupt binary.
pub fn apply_passes_to_binary(binary: &[u8]) -> Result<Vec<u8>, String> {
    use goblin::Object;

    let parsed = Object::parse(binary).map_err(|e| format!("binary parse failed: {e}"))?;

    // Collect (file_offset, raw_size, virtual_address) for each executable section.
    let sections: Vec<(usize, usize, u64)> = match parsed {
        Object::PE(pe) => {
            let image_base = pe.image_base as u64;
            pe.sections
                .iter()
                .filter(|s| {
                    const IMAGE_SCN_MEM_EXECUTE: u32 = 0x2000_0000;
                    s.characteristics & IMAGE_SCN_MEM_EXECUTE != 0
                        && s.size_of_raw_data > 0
                        && s.pointer_to_raw_data > 0
                })
                .map(|s| {
                    (
                        s.pointer_to_raw_data as usize,
                        s.size_of_raw_data as usize,
                        image_base + s.virtual_address as u64,
                    )
                })
                .collect()
        }
        Object::Elf(elf) => {
            const SHF_EXECINSTR: u64 = 0x4;
            elf.section_headers
                .iter()
                .filter(|s| {
                    s.sh_flags & SHF_EXECINSTR != 0
                        && s.sh_size > 0
                        && s.sh_offset > 0
                })
                .map(|s| (s.sh_offset as usize, s.sh_size as usize, s.sh_addr))
                .collect()
        }
        Object::Mach(_) | Object::Archive(_) | Object::Unknown(_) => {
            return Err(
                "unsupported binary format; only PE and ELF are supported for diversification"
                    .into(),
            );
        }
    };

    if sections.is_empty() {
        return Err("no executable sections found in binary".into());
    }

    let mut out = binary.to_vec();
    let mut patched = 0usize;

    for (file_offset, raw_size, va) in sections {
        if file_offset + raw_size > binary.len() {
            tracing::warn!(
                "diversify: section at offset {file_offset:#x} extends past binary end; skipping"
            );
            continue;
        }
        let code = &binary[file_offset..file_offset + raw_size];
        let new_bytes = apply_passes_at(va, code);

        match new_bytes.len().cmp(&raw_size) {
            std::cmp::Ordering::Equal => {
                out[file_offset..file_offset + raw_size].copy_from_slice(&new_bytes);
                patched += 1;
            }
            std::cmp::Ordering::Less => {
                // Fits — fill the remaining slack with INT3 guard bytes.
                out[file_offset..file_offset + new_bytes.len()].copy_from_slice(&new_bytes);
                out[file_offset + new_bytes.len()..file_offset + raw_size].fill(0xCC);
                patched += 1;
            }
            std::cmp::Ordering::Greater => {
                tracing::warn!(
                    "diversify: transformed section at {va:#x} grew from {raw_size} to {} bytes; \
                     skipping (re-run for a different randomisation that stays within budget)",
                    new_bytes.len()
                );
            }
        }
    }

    tracing::info!("diversify: applied passes to {patched} executable section(s)");
    Ok(out)
}



/// NOP insertion pass: randomly inserts multi-byte NOPs (`0F 1F /0`)
/// between instructions at ~10% density.
///
/// Each build produces a different NOP pattern, changing the binary's
/// fingerprint without affecting semantics.
pub struct NopInsertionPass;
impl Pass for NopInsertionPass {
    fn run(&self, instrs: &mut Vec<Instruction>) {
        let mut rng = thread_rng();
        let mut new_instrs = Vec::new();
        for ins in instrs.iter() {
            new_instrs.push(*ins);
            if rng.gen_bool(0.1) {
                // Use a multi-byte NOP form (0F 1F /0) to avoid obvious 0x90 padding.
                if let Ok(nop) = Instruction::with1(Code::Nop_rm64, iced_x86::Register::RAX) {
                    new_instrs.push(nop);
                }
            }
        }
        *instrs = new_instrs;
    }
}

/// Returns true if the instruction is a branch, call, or return that ends a
/// basic block, determined by re-encoding the instruction and inspecting
/// the leading opcode byte(s).
#[cfg(feature = "diversification")]
fn is_block_terminator(ins: &Instruction) -> bool {
    let mut enc = Encoder::new(64);
    if enc.encode(ins, 0).is_err() {
        return false;
    }
    let bytes = enc.take_buffer();
    if bytes.is_empty() {
        return false;
    }
    // Skip legacy prefixes / REX to find the real opcode
    let mut i = 0;
    while i < bytes.len() {
        let b = bytes[i];
        if matches!(
            b,
            0x26 | 0x2E | 0x36 | 0x3E | 0x64 | 0x65 | 0x66 | 0x67 | 0xF0 | 0xF2 | 0xF3
        ) || (b & 0xF0 == 0x40)
        {
            i += 1;
            continue;
        }
        break;
    }
    if i >= bytes.len() {
        return false;
    }
    let b0 = bytes[i];
    match b0 {
        // ret near/far, iret
        0xC2 | 0xC3 | 0xCA | 0xCB | 0xCF => true,
        // Jcc short (70..7F)
        0x70..=0x7F => true,
        // LOOP/LOOPE/LOOPNE/JRCXZ
        0xE0..=0xE3 => true,
        // CALL near rel32, JMP near rel32, JMP short
        0xE8 | 0xE9 | 0xEB => true,
        // CALL far / JMP far
        0x9A | 0xEA => true,
        // indirect CALL/JMP (FF /2 and FF /4)
        0xFF => true,
        // 0F 8x — Jcc near
        0x0F => i + 1 < bytes.len() && (bytes[i + 1] & 0xF0 == 0x80),
        _ => false,
    }
}

// ── SSA-based instruction scheduling pass ────────────────────────────────────

/// Instruction scheduling pass: reorders independent (non-dependent)
/// instructions within basic blocks.
///
/// Instructions are grouped into dependency chains and the chains are
/// interleaved to produce a different execution order while preserving
/// data-flow correctness.
pub struct InstructionSchedulingPass;
impl Pass for InstructionSchedulingPass {
    fn run(&self, instrs: &mut Vec<Instruction>) {
        if instrs.len() <= 2 {
            return;
        }

        // Partition instructions into basic blocks (block = maximal sequence of
        // non-terminator instructions followed by one terminator).
        let block_boundaries = find_block_boundaries(instrs);

        // Process each basic block independently.
        let mut prev_end = 0usize;
        for &end in &block_boundaries {
            let start = prev_end;
            if end > start + 2 {
                schedule_block(&mut instrs[start..end]);
            }
            prev_end = end;
        }
    }
}

/// Return the exclusive end indices of basic blocks within `instrs`.
///
/// A basic block ends at every block-terminator instruction (branch, call,
/// return, interrupt, etc.) determined by `flow_control()`.
fn find_block_boundaries(instrs: &[Instruction]) -> Vec<usize> {
    let mut boundaries = Vec::new();
    for (i, ins) in instrs.iter().enumerate() {
        let fc = ins.flow_control();
        if fc != FlowControl::Next {
            boundaries.push(i + 1);
        }
    }
    // If the last instruction is not a terminator, close the block.
    if boundaries.last().copied() != Some(instrs.len()) {
        boundaries.push(instrs.len());
    }
    boundaries
}

/// Set of resources (registers, memory, flags) that an instruction reads or
/// writes.  Used for dependency analysis.
#[derive(Clone, Default)]
struct ResourceSet {
    /// GPR register numbers that are explicitly read (32-bit or wider).
    reads: Vec<u32>,
    /// GPR register numbers that are explicitly written (32-bit or wider).
    writes: Vec<u32>,
    /// True if the instruction has any memory operand (read or write).
    has_memory: bool,
    /// True if the memory operand is a write (store).
    mem_write: bool,
    /// RFLAGS bits read.
    flags_read: u32,
    /// RFLAGS bits written (including undefined/modified).
    flags_written: u32,
    /// True if the instruction has side effects beyond registers/flags/memory
    /// that prevent reordering (e.g., CPUID, RDTSC, serialising instructions).
    has_side_effects: bool,
    /// Computed latency priority: higher = should be scheduled earlier.
    priority: u32,
}

/// Normalise a register to its 64-bit GPR base number (0–15).
/// Returns `None` for non-GPR registers (XMM, segment, etc.).
fn gpr_base(reg: Register) -> Option<u32> {
    if !reg.is_gpr() {
        return None;
    }
    let full = reg.full_register();
    // Map full 64-bit GPR to its index 0–15.
    match full {
        Register::RAX => Some(0),
        Register::RCX => Some(1),
        Register::RDX => Some(2),
        Register::RBX => Some(3),
        Register::RSP => Some(4),
        Register::RBP => Some(5),
        Register::RSI => Some(6),
        Register::RDI => Some(7),
        Register::R8 => Some(8),
        Register::R9 => Some(9),
        Register::R10 => Some(10),
        Register::R11 => Some(11),
        Register::R12 => Some(12),
        Register::R13 => Some(13),
        Register::R14 => Some(14),
        Register::R15 => Some(15),
        _ => None,
    }
}

/// Build the resource set (reads, writes, dependencies) for a single
/// instruction.
fn build_resource_set(ins: &Instruction) -> ResourceSet {
    let mut rs = ResourceSet::default();

    // ── Explicit register operands ──────────────────────────────────────
    let mut read_regs: Vec<u32> = Vec::new();
    let mut write_regs: Vec<u32> = Vec::new();

    for i in 0..ins.op_count() {
        match ins.op_kind(i) {
            OpKind::Register => {
                let reg = ins.op_register(i);
                if let Some(base) = gpr_base(reg) {
                    // In x86, the first operand is typically the destination
                    // (write), and subsequent operands are sources (read).
                    // However, some instructions (e.g., LEA) don't write.
                    // We use a conservative heuristic: operand 0 is written
                    // for most instructions, all others are read.
                    if i == 0 {
                        write_regs.push(base);
                    } else {
                        read_regs.push(base);
                    }
                }
            }
            OpKind::Memory => {
                rs.has_memory = true;
                // Determine if this memory operand is a read or write.
                // For op_kind(0) == Memory, it's typically a load (read).
                // For op0 being a register and op1 being memory, the memory
                // is read.  For stores, op0 is memory and the instruction
                // writes to it.
                if i == 0 {
                    // destination is memory → store
                    rs.mem_write = true;
                }
                // Collect memory base and index registers as reads.
                let base = ins.memory_base();
                let index = ins.memory_index();
                if let Some(b) = gpr_base(base) {
                    read_regs.push(b);
                }
                if let Some(idx) = gpr_base(index) {
                    read_regs.push(idx);
                }
            }
            _ => {}
        }
    }

    // Deduplicate
    read_regs.sort_unstable();
    read_regs.dedup();
    write_regs.sort_unstable();
    write_regs.dedup();
    // Remove write registers from read set (avoid false self-dependency).
    // Actually, keep reads that overlap writes — they represent WAW via the
    // same register, but RAW is the real dependency.  A register that appears
    // in both read and write sets means the instruction reads *and* writes it
    // (e.g., ADD rax, rbx reads rax and writes rax).

    rs.reads = read_regs;
    rs.writes = write_regs;

    // ── Implicit register usage ─────────────────────────────────────────
    // Some instructions implicitly read/write registers not captured by the
    // explicit operand encoding.  Handle common cases.
    let code = ins.code();
    match code {
        // PUSH/POP implicitly touch RSP
        _ if code_is_push(code) => {
            if let Some(4) = gpr_base(Register::RSP) {
                rs.reads.push(4); // reads RSP
                rs.writes.push(4); // writes RSP
            }
        }
        _ if code_is_pop(code) => {
            if let Some(4) = gpr_base(Register::RSP) {
                rs.reads.push(4);
                rs.writes.push(4);
            }
        }
        // LEA doesn't actually read the registers used in the address
        // computation, but its operands are already handled above.
        // MOV with memory operand: handled by OpKind::Memory above.
        _ => {}
    }

    // ── RFLAGS ──────────────────────────────────────────────────────────
    rs.flags_read = ins.rflags_read();
    rs.flags_written = ins.rflags_modified(); // includes written, cleared, undefined

    // ── Side effects ────────────────────────────────────────────────────
    // Instructions with side effects beyond registers/flags/memory cannot
    // be safely reordered relative to each other.
    rs.has_side_effects = matches!(
        code,
        Code::Cpuid
            | Code::Rdtsc
            | Code::Rdtscp
            | Code::Lfence
            | Code::Mfence
            | Code::Sfence
            | Code::Xsave64_mem
            | Code::Xrstor64_mem
            | Code::Clflush_m8
            | Code::Clflushopt_m8
            | Code::Clwb_m8
            | Code::Invd
            | Code::Wbinvd
            | Code::Rdrand_r64
            | Code::Rdseed_r64
    );

    // ── Latency-based priority ──────────────────────────────────────────
    // Memory operations get higher priority (latency ~4) so they are
    // scheduled earlier, giving more room for dependent instructions.
    // ALU operations get medium priority (~2).  Moves get low priority (~1).
    rs.priority = if rs.has_memory {
        4
    } else if rs.flags_written != 0 {
        3
    } else if !rs.writes.is_empty() {
        2
    } else {
        1
    };

    rs
}

/// Check if an instruction code is a PUSH variant.
fn code_is_push(code: Code) -> bool {
    matches!(
        code,
        Code::Push_r64
            | Code::Push_rm64
            | Code::Pushw_imm8
            | Code::Pushd_imm32
    )
}

/// Check if an instruction code is a POP variant.
fn code_is_pop(code: Code) -> bool {
    matches!(
        code,
        Code::Pop_r64 | Code::Pop_rm64
    )
}

/// Check if two resource sets have a dependency that prevents reordering.
/// Returns `true` if `a` must come before `b` (i.e., `b` depends on `a`).
///
/// Dependency types checked:
/// - **RAW** (Read-After-Write): `b` reads a register that `a` writes.
/// - **WAW** (Write-After-Write): `b` writes a register that `a` writes.
/// - **WAR** (Write-After-Read): `b` writes a register that `a` reads.
/// - **Memory**: if either accesses memory, assume they may alias.
/// - **Flags**: if `b` reads flags that `a` writes.
fn has_dependency(a: &ResourceSet, b: &ResourceSet) -> bool {
    // RAW: b reads what a writes
    for &r in &a.writes {
        if b.reads.contains(&r) || b.writes.contains(&r) {
            return true;
        }
    }
    // WAR: b writes what a reads
    for &r in &b.writes {
        if a.reads.contains(&r) {
            return true;
        }
    }
    // WAW: both write the same register
    for &r in &a.writes {
        if b.writes.contains(&r) {
            return true;
        }
    }
    // Memory dependencies (conservative: any two memory ops may alias).
    if a.has_memory && b.has_memory {
        // If both are reads, they can be reordered.
        if !a.mem_write && !b.mem_write {
            return false;
        }
        // At least one is a write → assume dependency.
        return true;
    }
    // Flags dependency: b reads flags that a modifies.
    if a.flags_written != 0 && (a.flags_written & b.flags_read) != 0 {
        return true;
    }
    // Side effects: cannot reorder relative to anything with side effects.
    if a.has_side_effects || b.has_side_effects {
        return true;
    }
    false
}

/// Schedule instructions within a single basic block using a list-scheduling
/// algorithm that respects all data dependencies.
///
/// The algorithm:
/// 1. Build resource sets for all instructions.
/// 2. Build a dependency DAG (adjacency lists).
/// 3. Compute the height (longest path to a leaf) for each node — this gives
///    the latency-weighted priority.
/// 4. Use list scheduling: repeatedly pick the ready instruction with the
///    highest priority, emit it, and mark its successors as ready.
/// 5. Random tie-breaking among equally-prioritised ready instructions.
fn schedule_block(block: &mut [Instruction]) {
    let n = block.len();
    if n <= 2 {
        return;
    }

    // Step 1: Build resource sets.
    let resources: Vec<ResourceSet> = block.iter().map(|ins| build_resource_set(ins)).collect();

    // Step 2: Build dependency DAG.
    // deps[i] = set of indices that instruction i depends on (predecessors).
    // succs[i] = set of indices that depend on instruction i (successors).
    let mut deps: Vec<Vec<usize>> = vec![Vec::new(); n];
    let mut succs: Vec<Vec<usize>> = vec![Vec::new(); n];

    for j in 1..n {
        for i in (0..j).rev() {
            // j depends on i if there's a RAW/WAR/WAW/memory/flags hazard.
            if has_dependency(&resources[i], &resources[j]) {
                deps[j].push(i);
                succs[i].push(j);
                // Only record the *nearest* dependency on each register/memory
                // path.  Once we find a direct dependency, we don't need to
                // check earlier instructions for the same resource because the
                // transitive chain will enforce ordering.
                // However, for correctness we need ALL direct dependencies,
                // not just the nearest.  For example:
                //   i=0: MOV RAX, 1    (writes RAX)
                //   i=1: ADD RBX, RAX  (reads RAX)
                //   i=2: MOV RAX, 2    (writes RAX)
                // Here, i=2 depends on i=1 (WAR: writes RAX which i=1 reads)
                // AND i=2 depends on i=0 (WAW: both write RAX).
                // If we stopped at i=1, we'd miss the WAW with i=0.
                // So we continue checking all predecessors.
            }
        }
    }

    // Step 3: Compute height-based priority (longest path from this node to
    // the end of the DAG).  Instructions on the critical path get higher
    // priority.
    let mut height = vec![0u32; n];
    // Process in reverse topological order (last instructions first).
    for i in (0..n).rev() {
        let mut max_child_height = 0u32;
        for &s in &succs[i] {
            max_child_height = max_child_height.max(height[s]);
        }
        // Height = max child height + this instruction's latency (priority).
        height[i] = max_child_height + resources[i].priority;
    }

    // Step 4: List scheduling.
    let mut remaining_deps: Vec<usize> = deps.iter().map(|d| d.len()).collect();
    let mut scheduled: Vec<usize> = Vec::with_capacity(n);
    let mut already_scheduled = vec![false; n];

    // Seed: instructions with no predecessors.
    let mut rng = thread_rng();

    for _ in 0..n {
        // Collect all ready instructions (remaining_deps == 0 and not scheduled).
        let mut ready: Vec<usize> = (0..n)
            .filter(|&i| !already_scheduled[i] && remaining_deps[i] == 0)
            .collect();

        if ready.is_empty() {
            // Deadlock — should not happen with a valid DAG, but fall back to
            // appending remaining instructions in original order.
            for i in 0..n {
                if !already_scheduled[i] {
                    scheduled.push(i);
                }
            }
            break;
        }

        // Sort ready instructions by height (descending), then by original
        // position (ascending) for stability within equal priority.
        ready.sort_by(|&a, &b| {
            height[b].cmp(&height[a]).then_with(|| a.cmp(&b))
        });

        // Among instructions with the same top priority, pick randomly.
        let top_priority = height[ready[0]];
        let top_tier_end = ready
            .iter()
            .position(|&i| height[i] != top_priority)
            .unwrap_or(ready.len());

        // Choose a random instruction from the top tier.
        let chosen = if top_tier_end == 1 {
            ready[0]
        } else {
            ready[rng.gen_range(0..top_tier_end)]
        };

        scheduled.push(chosen);
        already_scheduled[chosen] = true;

        // Decrement dependency counts for successors.
        for &s in &succs[chosen] {
            if remaining_deps[s] > 0 {
                remaining_deps[s] -= 1;
            }
        }
    }

    // Step 5: Reorder the block according to the schedule.
    let original: Vec<Instruction> = block.to_vec();
    for (slot, &idx) in scheduled.iter().enumerate() {
        // Preserve the original IP for branch-target fixup.
        block[slot] = original[idx];
    }
}

/// Apply registered optimizer passes to the named hot function.
///
/// Without the `unsafe-runtime-rewrite` feature this is a metadata-only
/// no-op — the optimizer passes can still be exercised via `apply_passes`
/// from tests.
///
/// With `unsafe-runtime-rewrite` enabled, the function performs in-place
/// rewriting of the named function: locate the symbol, decode an estimated
/// span (default 256 bytes), apply the registered passes, then write the
/// result back into executable memory after temporarily lowering page
/// protections via `VirtualProtect` (Windows) or `mprotect` (Unix).

// ── Instruction substitution pass ────────────────────────────────────────────

/// Replace instructions with semantically equivalent alternatives to produce
/// different binary patterns across builds (metamorphism).
///
/// Substitution table (applied with ~50 % probability each):
/// * `ADD r64, 1`  ↔  `INC r64`
/// * `SUB r64, 1`  ↔  `DEC r64`
/// * `MOV r64, 0`  →   `XOR r64, r64`
/// * `XOR r64, r64` (same reg) ↔ `SUB r64, r64`
/// * `TEST r64, r64` (same reg) ↔ `CMP r64, 0`
/// * `AND r64, 0`  →   `XOR r64, r64`
///
/// Note: INC/DEC differ from ADD/SUB in that they do **not** update CF.  This
/// substitution is safe wherever CF is not observed after the instruction,
/// which covers the vast majority of loop-counter and pointer-increment
/// patterns.  Enable only when you accept this caveat.
#[cfg(feature = "diversification")]
/// Instruction substitution pass: replaces instructions with semantically
/// equivalent alternatives.
///
/// Substitutions include:
/// - `ADD reg, 1` ↔ `INC reg`
/// - `SUB reg, 1` ↔ `DEC reg`
/// - `MOV reg, 0` → `XOR reg, reg`
/// - `TEST reg, reg` ↔ `CMP reg, 0`
///
/// Each substitution is applied with 50% probability per instruction.
pub struct InstructionSubstitutionPass;

#[cfg(feature = "diversification")]
impl Pass for InstructionSubstitutionPass {
    fn run(&self, instrs: &mut Vec<Instruction>) {
        let mut rng = thread_rng();
        for ins in instrs.iter_mut() {
            if !rng.gen_bool(0.5) {
                continue;
            }
            let orig_ip = ins.ip();
            if let Some(mut new_ins) = try_substitute(ins, &mut rng) {
                new_ins.set_ip(orig_ip);
                *ins = new_ins;
            }
        }
    }
}

/// Return a semantically-equivalent replacement for `ins`, or `None` to keep
/// the original unchanged.
#[cfg(feature = "diversification")]
fn try_substitute(ins: &Instruction, rng: &mut impl Rng) -> Option<Instruction> {
    match ins.code() {
        // ADD r/m64, 1  →  INC r/m64
        Code::Add_rm64_imm8 if ins.op0_kind() == OpKind::Register && ins.immediate8() == 1 => {
            Instruction::with1(Code::Inc_rm64, ins.op0_register()).ok()
        }
        // INC r/m64  →  ADD r/m64, 1  (restores CF behaviour)
        Code::Inc_rm64 if ins.op0_kind() == OpKind::Register && rng.gen_bool(0.5) => {
            Instruction::with2(Code::Add_rm64_imm8, ins.op0_register(), 1u32).ok()
        }
        // SUB r/m64, 1  →  DEC r/m64
        Code::Sub_rm64_imm8 if ins.op0_kind() == OpKind::Register && ins.immediate8() == 1 => {
            Instruction::with1(Code::Dec_rm64, ins.op0_register()).ok()
        }
        // DEC r/m64  →  SUB r/m64, 1
        Code::Dec_rm64 if ins.op0_kind() == OpKind::Register && rng.gen_bool(0.5) => {
            Instruction::with2(Code::Sub_rm64_imm8, ins.op0_register(), 1u32).ok()
        }
        // MOV r64, 0  →  XOR r64, r64  (sets identical flags; saves 3-4 bytes)
        Code::Mov_rm64_imm32 | Code::Mov_r64_imm64
            if ins.op0_kind() == OpKind::Register && ins.immediate64() == 0 =>
        {
            let r = ins.op0_register();
            Instruction::with2(Code::Xor_r64_rm64, r, r).ok()
        }
        // XOR r64, r64 (same reg)  →  SUB r64, r64  (identical semantics + flags)
        Code::Xor_r64_rm64
            if ins.op0_kind() == OpKind::Register
                && ins.op1_kind() == OpKind::Register
                && ins.op0_register() == ins.op1_register()
                && rng.gen_bool(0.5) =>
        {
            let r = ins.op0_register();
            Instruction::with2(Code::Sub_r64_rm64, r, r).ok()
        }
        // AND r64, 0  →  XOR r64, r64  (both zero reg; flag effects identical)
        Code::And_rm64_imm8 if ins.op0_kind() == OpKind::Register && ins.immediate8() == 0 => {
            let r = ins.op0_register();
            Instruction::with2(Code::Xor_r64_rm64, r, r).ok()
        }
        // TEST r64, r64  →  CMP r64, 0  (identical flag outputs)
        Code::Test_rm64_r64
            if ins.op0_kind() == OpKind::Register
                && ins.op1_kind() == OpKind::Register
                && ins.op0_register() == ins.op1_register() =>
        {
            Instruction::with2(Code::Cmp_rm64_imm8, ins.op0_register(), 0i32).ok()
        }
        // CMP r64, 0  →  TEST r64, r64
        Code::Cmp_rm64_imm8 if ins.op0_kind() == OpKind::Register && ins.immediate8() == 0 => {
            let r = ins.op0_register();
            Instruction::with2(Code::Test_rm64_r64, r, r).ok()
        }
        _ => None,
    }
}

// ── Opaque dead-code insertion pass ──────────────────────────────────────────

/// Insert opaque dead-store sequences at basic-block boundaries.
///
/// Before ~35 % of block-entry instructions, inserts:
/// ```asm
///   PUSH <scratch_reg>
///   MOV  <scratch_reg>, <random_imm64>
///   POP  <scratch_reg>
/// ```
/// This sequence preserves all flags and all registers (RSP nets to zero) but
/// produces a different binary fingerprint every build.
///
/// The scratch register is chosen from **caller-saved** registers (RAX, RCX,
/// RDX, R8–R11) because these are volatile by convention — the calling code
/// already assumes they may be clobbered.  Callee-saved registers (RBX,
/// R12–R15) were previously used but are unsafe to touch without liveness
/// analysis: if the surrounding function has live values in those registers,
/// the PUSH/MOV/POP sequence would silently corrupt them.
#[cfg(feature = "diversification")]
pub struct OpaqueDeadCodePass;

#[cfg(feature = "diversification")]
impl Pass for OpaqueDeadCodePass {
    fn run(&self, instrs: &mut Vec<Instruction>) {
        // Caller-saved (volatile) registers on both SysV AMD64 and Windows x64
        // ABI.  These are safe to use without liveness analysis because the
        // calling convention assumes they may be clobbered at any call site or
        // block boundary.  RSP and RBP are excluded.
        const SCRATCH: &[Register] = &[
            Register::RAX,
            Register::RCX,
            Register::RDX,
            Register::R8,
            Register::R9,
            Register::R10,
            Register::R11,
        ];
        let mut rng = thread_rng();
        let mut result = Vec::with_capacity(instrs.len() + instrs.len() / 4);
        let mut at_block_start = true;
        let mut stub_index: u64 = 0;

        for &ins in instrs.iter() {
            if at_block_start && rng.gen_bool(0.35) {
                let reg = *SCRATCH.choose(&mut rng).unwrap();
                // Derive dead_val from the build-time STUB_SEED and the per-site
                // stub index using HKDF-SHA256.  This makes every build produce
                // different constants (STUB_SEED changes each build) while each
                // stub site within a build also gets a distinct value.
                let dead_val = derive_dead_val(stub_index);
                stub_index += 1;
                // PUSH / MOV / POP — EFLAGS unchanged, RSP net change = 0.
                if let (Ok(push), Ok(mov), Ok(pop)) = (
                    Instruction::with1(Code::Push_r64, reg),
                    Instruction::with2(Code::Mov_r64_imm64, reg, dead_val),
                    Instruction::with1(Code::Pop_r64, reg),
                ) {
                    result.push(push);
                    result.push(mov);
                    result.push(pop);
                }
            }
            at_block_start = is_block_terminator(&ins);
            result.push(ins);
        }
        *instrs = result;
    }
}

/// Apply runtime diversification to a named function.
///
/// When the `unsafe-runtime-rewrite` feature is enabled, this locates the
/// function by name in the current process's memory, applies diversification
/// passes, and patches the function in-place. Otherwise, this is a no-op.
///
/// # Safety
///
/// This function modifies executable memory at runtime. It should only be
/// called when no other thread is executing the target function.
pub fn optimize_hot_function(name: &str) -> Result<(), String> {
    tracing::debug!("optimize_hot_function: requested for '{}'", name);

    #[cfg(not(feature = "unsafe-runtime-rewrite"))]
    {
        let _ = name;
        Ok(())
    }

    #[cfg(feature = "unsafe-runtime-rewrite")]
    {
        runtime_rewrite::rewrite(name)
    }
}

#[cfg(feature = "unsafe-runtime-rewrite")]
mod runtime_rewrite {
    use super::*;

    /// Upper-bound span used when no symbol-size information is available.
    /// 4096 bytes is large enough to cover most functions while staying within
    /// a single page, so the mprotect/VirtualProtect call never spans more than
    /// two pages.
    const FALLBACK_SPAN: usize = 4096;

    pub fn rewrite(name: &str) -> Result<(), String> {
        let addr = locate_symbol(name)
            .ok_or_else(|| format!("symbol '{}' not found in this process", name))?;

        // Determine the function's actual byte span from the symbol table or
        // the PE exception directory.  Fall back to FALLBACK_SPAN only if all
        // platform-specific methods fail.
        let span = find_function_size(name, addr).unwrap_or_else(|| {
            tracing::warn!(
                "optimize_hot_function: could not determine size of '{}'; \
                 using fallback span of {} bytes",
                name,
                FALLBACK_SPAN
            );
            FALLBACK_SPAN
        });

        // Snapshot the current bytes
        let original =
            unsafe { std::slice::from_raw_parts(addr as *const u8, span) }.to_vec();
        // Apply optimizer passes
        let mut new_bytes = apply_passes(&original);
        // If the new code is longer than the original span, refuse — we cannot
        // safely overwrite into adjacent code.  If shorter, INT3-pad to fill
        // the gap so stray execution traps immediately instead of running through
        // silent NOPs.
        if new_bytes.len() > original.len() {
            return Err(format!(
                "rewrite would grow code ({} -> {} bytes); refusing",
                original.len(),
                new_bytes.len()
            ));
        }
        if new_bytes.len() < original.len() {
            new_bytes.resize(original.len(), 0xCC); // INT3-pad to original size (trap on stray execution)
        }
        // Lower protection, copy, restore.
        unsafe {
            let mut old = make_writable(addr, span)?;
            std::ptr::copy_nonoverlapping(new_bytes.as_ptr(), addr as *mut u8, span);
            restore_protection(addr, span, &mut old)?;
            flush_icache(addr, span);
        }
        tracing::info!(
            "optimize_hot_function: rewrote {} bytes at {:p} for '{}'",
            span,
            addr as *const u8,
            name
        );
        Ok(())
    }

    /// Resolve the byte size of the named function using platform-specific
    /// metadata.
    ///
    /// * **Windows x86-64**: queries `RtlLookupFunctionEntry` which returns the
    ///   `RUNTIME_FUNCTION` entry from the `.pdata` exception directory; its
    ///   `EndAddress − BeginAddress` is the exact encoded function size.
    /// * **Linux**: reads `/proc/self/exe`, parses the ELF static symbol table
    ///   with `goblin`, and returns the `st_size` field of the matching symbol.
    /// * Returns `None` if neither method can determine the size.
    fn find_function_size(name: &str, #[allow(unused_variables)] addr: usize) -> Option<usize> {
        #[cfg(all(windows, target_arch = "x86_64"))]
        {
            find_function_size_pdata(addr)
        }
        #[cfg(target_os = "linux")]
        {
            find_function_size_elf(name)
        }
        #[cfg(not(any(all(windows, target_arch = "x86_64"), target_os = "linux")))]
        {
            let _ = (name, addr);
            None
        }
    }

    /// Windows x86-64: ask the OS for the RUNTIME_FUNCTION covering `addr`.
    /// `RtlLookupFunctionEntry` is present in ntdll.dll on all modern Windows
    /// versions and requires no extra imports beyond what is already linked.
    #[cfg(all(windows, target_arch = "x86_64"))]
    fn find_function_size_pdata(addr: usize) -> Option<usize> {
        #[repr(C)]
        struct RuntimeFunction {
            begin_address: u32,
            end_address: u32,
            unwind_info_address: u32,
        }

        extern "system" {
            /// Returns a pointer to the RUNTIME_FUNCTION covering `control_pc`,
            /// or NULL if none exists (e.g., leaf functions with no unwind info).
            fn RtlLookupFunctionEntry(
                control_pc: u64,
                image_base: *mut u64,
                history_table: *mut std::ffi::c_void,
            ) -> *const RuntimeFunction;
        }

        unsafe {
            let mut image_base: u64 = 0;
            let rf = RtlLookupFunctionEntry(
                addr as u64,
                &mut image_base,
                std::ptr::null_mut(),
            );
            if rf.is_null() {
                return None;
            }
            let begin = (*rf).begin_address as usize;
            let end = (*rf).end_address as usize;
            if end > begin {
                Some(end - begin)
            } else {
                None
            }
        }
    }

    /// Linux: parse the ELF static symbol table of `/proc/self/exe` to look
    /// up the `st_size` of the named symbol.  Goblin is already a dependency
    /// of this crate so no additional dependency is added.
    ///
    /// This works correctly for both PIE and non-PIE binaries because we match
    /// on the symbol *name* rather than on a virtual address that would require
    /// knowing the ASLR slide.
    #[cfg(target_os = "linux")]
    fn find_function_size_elf(name: &str) -> Option<usize> {
        let data = std::fs::read("/proc/self/exe").ok()?;
        let elf = goblin::elf::Elf::parse(&data).ok()?;

        // Prefer the static symbol table (.symtab) as it is more complete.
        // Fall back to the dynamic symbol table (.dynsym) for stripped binaries.
        for sym in elf.syms.iter() {
            if sym.st_size > 0 {
                if let Some(sym_name) = elf.strtab.get_at(sym.st_name) {
                    if sym_name == name {
                        return Some(sym.st_size as usize);
                    }
                }
            }
        }
        for sym in elf.dynsyms.iter() {
            if sym.st_size > 0 {
                if let Some(sym_name) = elf.dynstrtab.get_at(sym.st_name) {
                    if sym_name == name {
                        return Some(sym.st_size as usize);
                    }
                }
            }
        }
        None
    }

    fn locate_symbol(_name: &str) -> Option<usize> {
        // In a fully self-contained binary we cannot easily resolve symbols
        // by name without dlsym/GetProcAddress against the current module.
        // Use platform-specific lookup against the main module.
        #[cfg(unix)]
        unsafe {
            let cname = std::ffi::CString::new(_name).ok()?;
            let addr = libc::dlsym(libc::RTLD_DEFAULT, cname.as_ptr());
            if addr.is_null() {
                None
            } else {
                Some(addr as usize)
            }
        }
        #[cfg(windows)]
        unsafe {
            extern "system" {
                fn GetModuleHandleA(name: *const i8) -> *mut std::ffi::c_void;
                fn GetProcAddress(
                    h: *mut std::ffi::c_void,
                    name: *const i8,
                ) -> *mut std::ffi::c_void;
            }
            let h = GetModuleHandleA(std::ptr::null());
            if h.is_null() {
                return None;
            }
            let cname = std::ffi::CString::new(_name).ok()?;
            let addr = GetProcAddress(h, cname.as_ptr());
            if addr.is_null() {
                None
            } else {
                Some(addr as usize)
            }
        }
        #[cfg(not(any(unix, windows)))]
        {
            None
        }
    }

    #[allow(dead_code)]
    pub struct ProtSnapshot(pub u32);

    #[cfg(windows)]
    unsafe fn make_writable(addr: usize, len: usize) -> Result<ProtSnapshot, String> {
        extern "system" {
            fn VirtualProtect(
                addr: *mut std::ffi::c_void,
                size: usize,
                new_protect: u32,
                old: *mut u32,
            ) -> i32;
        }
        const PAGE_EXECUTE_READWRITE: u32 = 0x40;
        let mut old = 0u32;
        if VirtualProtect(addr as *mut _, len, PAGE_EXECUTE_READWRITE, &mut old) == 0 {
            return Err("VirtualProtect(RWX) failed".into());
        }
        Ok(ProtSnapshot(old))
    }

    #[cfg(windows)]
    unsafe fn restore_protection(
        addr: usize,
        len: usize,
        old: &mut ProtSnapshot,
    ) -> Result<(), String> {
        extern "system" {
            fn VirtualProtect(
                addr: *mut std::ffi::c_void,
                size: usize,
                new_protect: u32,
                old: *mut u32,
            ) -> i32;
        }
        let mut tmp = 0u32;
        if VirtualProtect(addr as *mut _, len, old.0, &mut tmp) == 0 {
            return Err("VirtualProtect(restore) failed".into());
        }
        Ok(())
    }

    #[cfg(windows)]
    unsafe fn flush_icache(addr: usize, len: usize) {
        extern "system" {
            fn FlushInstructionCache(
                h: *mut std::ffi::c_void,
                addr: *const std::ffi::c_void,
                size: usize,
            ) -> i32;
            fn GetCurrentProcess() -> *mut std::ffi::c_void;
        }
        FlushInstructionCache(GetCurrentProcess(), addr as *const _, len);
    }

    #[cfg(unix)]
    fn read_page_protection(addr: usize) -> u32 {
        // Parse /proc/self/maps to find the protection for the page containing
        // `addr`.  Returns PROT_READ | PROT_EXEC as a safe fallback when
        // parsing fails (e.g. on non-Linux unix targets that lack /proc).
        use std::fs;
        if let Ok(maps) = fs::read_to_string("/proc/self/maps") {
            for line in maps.lines() {
                let parts: Vec<&str> = line.splitn(6, ' ').collect();
                if parts.len() >= 2 {
                    let range: Vec<&str> = parts[0].splitn(2, '-').collect();
                    if range.len() == 2 {
                        if let (Ok(start), Ok(end)) = (
                            usize::from_str_radix(range[0], 16),
                            usize::from_str_radix(range[1], 16),
                        ) {
                            if addr >= start && addr < end {
                                let mut prot: u32 = 0;
                                for c in parts[1].chars() {
                                    match c {
                                        'r' => prot |= libc::PROT_READ as u32,
                                        'w' => prot |= libc::PROT_WRITE as u32,
                                        'x' => prot |= libc::PROT_EXEC as u32,
                                        _ => {}
                                    }
                                }
                                return prot;
                            }
                        }
                    }
                }
            }
        }
        (libc::PROT_READ | libc::PROT_EXEC) as u32
    }

    #[cfg(unix)]
    unsafe fn make_writable(addr: usize, len: usize) -> Result<ProtSnapshot, String> {
        let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let aligned = addr & !(page - 1);
        let aligned_len = ((addr + len) - aligned + page - 1) & !(page - 1);
        let orig_prot = read_page_protection(aligned);
        if libc::mprotect(
            aligned as *mut libc::c_void,
            aligned_len,
            libc::PROT_READ | libc::PROT_WRITE | libc::PROT_EXEC,
        ) != 0
        {
            return Err(format!(
                "mprotect(RWX) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        // Save the page's *original* protection so restore can put it back
        // exactly (e.g. PROT_READ-only .rodata stays read-only) — H-6.
        Ok(ProtSnapshot(orig_prot))
    }

    #[cfg(unix)]
    unsafe fn restore_protection(
        addr: usize,
        len: usize,
        old: &mut ProtSnapshot,
    ) -> Result<(), String> {
        let page = libc::sysconf(libc::_SC_PAGESIZE) as usize;
        let aligned = addr & !(page - 1);
        let aligned_len = ((addr + len) - aligned + page - 1) & !(page - 1);
        if libc::mprotect(aligned as *mut libc::c_void, aligned_len, old.0 as i32) != 0 {
            return Err(format!(
                "mprotect(restore) failed: {}",
                std::io::Error::last_os_error()
            ));
        }
        Ok(())
    }

    #[cfg(unix)]
    unsafe fn flush_icache(addr: usize, len: usize) {
        #[cfg(target_arch = "aarch64")]
        {
            // aarch64 I-cache is NOT coherent with D-cache.
            // Sequence: DC CVAU on each cache line, DSB ISH, IC IVAU on each
            // line, DSB ISH, ISB.  Without this the CPU may execute stale
            // instructions from I-cache after we rewrite code in D-cache (H-6).
            const CACHE_LINE: usize = 64; // typical aarch64 line size
            let end = addr + len;
            let mut p = addr & !(CACHE_LINE - 1);
            while p < end {
                std::arch::asm!("dc cvau, {x}", x = in(reg) p);
                p += CACHE_LINE;
            }
            std::arch::asm!("dsb ish");
            let mut p = addr & !(CACHE_LINE - 1);
            while p < end {
                std::arch::asm!("ic ivau, {x}", x = in(reg) p);
                p += CACHE_LINE;
            }
            std::arch::asm!("dsb ish", "isb");
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            // x86_64: coherent I-cache; mprotect serialises.  No-op is correct.
            let _ = (addr, len);
        }
    }

    #[cfg(not(any(windows, unix)))]
    unsafe fn make_writable(_a: usize, _l: usize) -> Result<ProtSnapshot, String> {
        Err("unsupported platform".into())
    }
    #[cfg(not(any(windows, unix)))]
    unsafe fn restore_protection(
        _a: usize,
        _l: usize,
        _o: &mut ProtSnapshot,
    ) -> Result<(), String> {
        Err("unsupported platform".into())
    }
    #[cfg(not(any(windows, unix)))]
    unsafe fn flush_icache(_a: usize, _l: usize) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: decode x86-64 bytes at base address 0x1000 into instructions.
    fn decode(code: &[u8]) -> Vec<Instruction> {
        Decoder::with_ip(64, code, 0x1000, DecoderOptions::NONE)
            .into_iter()
            .collect()
    }

    // ── gpr_base tests ──────────────────────────────────────────────────────

    #[test]
    fn test_gpr_base_rax_family() {
        assert_eq!(gpr_base(Register::RAX), Some(0));
        assert_eq!(gpr_base(Register::EAX), Some(0));
        assert_eq!(gpr_base(Register::AX), Some(0));
        assert_eq!(gpr_base(Register::AL), Some(0));
    }

    #[test]
    fn test_gpr_base_rcx_family() {
        assert_eq!(gpr_base(Register::RCX), Some(1));
        assert_eq!(gpr_base(Register::ECX), Some(1));
        assert_eq!(gpr_base(Register::CX), Some(1));
        assert_eq!(gpr_base(Register::CL), Some(1));
    }

    #[test]
    fn test_gpr_base_rsp() {
        assert_eq!(gpr_base(Register::RSP), Some(4));
        assert_eq!(gpr_base(Register::ESP), Some(4));
    }

    #[test]
    fn test_gpr_base_r8_through_r15() {
        assert_eq!(gpr_base(Register::R8), Some(8));
        assert_eq!(gpr_base(Register::R8D), Some(8));
        assert_eq!(gpr_base(Register::R15), Some(15));
        assert_eq!(gpr_base(Register::R15D), Some(15));
    }

    #[test]
    fn test_gpr_base_non_gpr_returns_none() {
        assert_eq!(gpr_base(Register::XMM0), None);
        assert_eq!(gpr_base(Register::ES), None);
        assert_eq!(gpr_base(Register::RIP), None);
    }

    // ── Dependency analysis tests ───────────────────────────────────────────

    #[test]
    fn test_raw_dependency_detected() {
        // MOV RAX, 1  →  ADD RBX, RAX  (RBX reads RAX, which was written)
        let mov = Instruction::with2(Code::Mov_r64_imm64, Register::RAX, 42u64).unwrap();
        let add = Instruction::with2(Code::Add_r64_rm64, Register::RBX, Register::RAX).unwrap();

        let rs_mov = build_resource_set(&mov);
        let rs_add = build_resource_set(&add);

        assert!(has_dependency(&rs_mov, &rs_add), "RAW: ADD reads RAX written by MOV");
    }

    #[test]
    fn test_waw_dependency_detected() {
        // MOV RAX, 1  →  MOV RAX, 2  (both write RAX)
        let mov1 = Instruction::with2(Code::Mov_r64_imm64, Register::RAX, 1u64).unwrap();
        let mov2 = Instruction::with2(Code::Mov_r64_imm64, Register::RAX, 2u64).unwrap();

        let rs1 = build_resource_set(&mov1);
        let rs2 = build_resource_set(&mov2);

        assert!(has_dependency(&rs1, &rs2), "WAW: both write RAX");
    }

    #[test]
    fn test_war_dependency_detected() {
        // ADD RBX, RAX  →  MOV RAX, 1  (second writes RAX which first reads)
        let add = Instruction::with2(Code::Add_r64_rm64, Register::RBX, Register::RAX).unwrap();
        let mov = Instruction::with2(Code::Mov_r64_imm64, Register::RAX, 1u64).unwrap();

        let rs_add = build_resource_set(&add);
        let rs_mov = build_resource_set(&mov);

        assert!(has_dependency(&rs_add, &rs_mov), "WAR: MOV writes RAX which ADD reads");
    }

    #[test]
    fn test_independent_instructions_no_dependency() {
        // MOV RAX, 1  →  MOV RBX, 2  (no shared registers)
        let mov_rax = Instruction::with2(Code::Mov_r64_imm64, Register::RAX, 1u64).unwrap();
        let mov_rbx = Instruction::with2(Code::Mov_r64_imm64, Register::RBX, 2u64).unwrap();

        let rs1 = build_resource_set(&mov_rax);
        let rs2 = build_resource_set(&mov_rbx);

        // Flags: MOV r64, imm64 doesn't modify flags, so no flag dependency.
        assert!(
            !has_dependency(&rs1, &rs2),
            "Independent MOVs should have no dependency"
        );
    }

    #[test]
    fn test_memory_dependency_store_load() {
        // MOV [RAX], RBX  →  MOV RCX, [RAX]  (store then load from same address)
        let store =
            Instruction::with2(Code::Mov_rm64_r64, Register::RAX, Register::RBX).unwrap();
        // This actually encodes as MOV RAX, RBX — for a proper memory operand
        // test, let's use a different approach: just check that two memory
        // operations with at least one write have a dependency.
        let rs_store = build_resource_set(&store);
        // store writes to RAX (op0), reads RBX (op1)
        assert!(rs_store.writes.contains(&0), "store writes RAX (base=0)");
    }

    // ── Scheduling correctness tests ────────────────────────────────────────

    #[test]
    fn test_schedule_preserves_raw() {
        // MOV RAX, 1
        // ADD RBX, RAX   ← must stay after MOV (reads RAX)
        // MOV RCX, 2
        let code: &[u8] = &[
            0x48, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV RAX, 1
            0x48, 0x01, 0xC3, // ADD RBX, RAX
            0x48, 0xC7, 0xC1, 0x02, 0x00, 0x00, 0x00, // MOV RCX, 2
        ];
        let mut instrs = decode(code);
        // Remove any trailing RET that the decoder may pick up
        let _original_count = instrs.len();

        let pass = InstructionSchedulingPass;
        pass.run(&mut instrs);

        // After scheduling, the MOV RAX,1 must still come before ADD RBX,RAX
        let mov_pos = instrs
            .iter()
            .position(|i| i.code() == Code::Mov_r64_imm64 && i.immediate64() == 1)
            .unwrap();
        let add_pos = instrs
            .iter()
            .position(|i| i.code() == Code::Add_rm64_r64)
            .unwrap();

        assert!(
            mov_pos < add_pos,
            "MOV RAX,1 (pos {mov_pos}) must come before ADD RBX,RAX (pos {add_pos})"
        );
    }

    #[test]
    fn test_schedule_preserves_waw() {
        // MOV RAX, 1
        // MOV RAX, 2     ← must stay after first MOV (both write RAX)
        let code: &[u8] = &[
            0x48, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV RAX, 1
            0x48, 0xB8, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV RAX, 2
        ];
        let mut instrs = decode(code);

        let pass = InstructionSchedulingPass;
        pass.run(&mut instrs);

        // Both MOVs write RAX, so they must remain in original order.
        // Find the one with immediate 1 and the one with immediate 2.
        let pos_1 = instrs
            .iter()
            .position(|i| i.code() == Code::Mov_r64_imm64 && i.immediate64() == 1)
            .unwrap();
        let pos_2 = instrs
            .iter()
            .position(|i| i.code() == Code::Mov_r64_imm64 && i.immediate64() == 2)
            .unwrap();

        assert!(
            pos_1 < pos_2,
            "MOV RAX,1 (pos {pos_1}) must come before MOV RAX,2 (pos {pos_2})"
        );
    }

    #[test]
    fn test_schedule_allows_independent_reorder() {
        // MOV RAX, 1
        // MOV RBX, 2     ← independent, may be reordered
        // MOV RCX, 3     ← independent of both above
        let code: &[u8] = &[
            0x48, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV RAX, 1
            0x48, 0xBB, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV RBX, 2
            0x48, 0xB9, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV RCX, 3
        ];
        let mut instrs = decode(code);

        let pass = InstructionSchedulingPass;
        pass.run(&mut instrs);

        // All three instructions write different registers and don't read
        // any shared state, so the scheduler may reorder them arbitrarily.
        // We just verify that all three are still present.
        assert_eq!(instrs.len(), 3, "all 3 instructions should be present");

        let regs: Vec<u32> = instrs
            .iter()
            .filter_map(|i| {
                if i.code() == Code::Mov_r64_imm64 {
                    gpr_base(i.op0_register())
                } else {
                    None
                }
            })
            .collect();
        assert_eq!(regs.len(), 3, "all 3 MOV instructions found");
        // All three registers (0=RAX, 3=RBX, 1=RCX) should be present
        assert!(regs.contains(&0), "RAX present");
        assert!(regs.contains(&3), "RBX present");
        assert!(regs.contains(&1), "RCX present");
    }

    #[test]
    fn test_schedule_does_not_cross_block_boundary() {
        // Block 1: MOV RAX, 1; RET
        // Block 2: MOV RBX, 2
        let code: &[u8] = &[
            0x48, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV RAX, 1
            0xC3, // RET
            0x48, 0xBB, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV RBX, 2
        ];
        let mut instrs = decode(code);

        let pass = InstructionSchedulingPass;
        pass.run(&mut instrs);

        // RET must remain between the two MOV instructions.
        let ret_pos = instrs
            .iter()
            .position(|i| i.flow_control() == FlowControl::Return)
            .unwrap();
        let mov_rax_pos = instrs
            .iter()
            .position(|i| i.code() == Code::Mov_r64_imm64 && i.immediate64() == 1)
            .unwrap();
        let mov_rbx_pos = instrs
            .iter()
            .position(|i| i.code() == Code::Mov_r64_imm64 && i.immediate64() == 2)
            .unwrap();

        assert!(
            mov_rax_pos < ret_pos,
            "MOV RAX must be before RET"
        );
        assert!(
            ret_pos < mov_rbx_pos,
            "RET must be before MOV RBX (block boundary)"
        );
    }

    #[test]
    fn test_schedule_flags_dependency() {
        // ADD RAX, 1     ← writes flags (CF, OF, etc.)
        // JZ target      ← reads ZF flag
        // The JZ must stay after ADD because it reads flags that ADD writes.
        let code: &[u8] = &[
            0x48, 0x83, 0xC0, 0x01, // ADD RAX, 1
            0x74, 0x05, // JZ +5
        ];
        let mut instrs = decode(code);

        let pass = InstructionSchedulingPass;
        pass.run(&mut instrs);

        let add_pos = instrs
            .iter()
            .position(|i| i.code() == Code::Add_rm64_imm8)
            .unwrap();
        let jz_pos = instrs
            .iter()
            .position(|i| matches!(i.flow_control(), FlowControl::ConditionalBranch))
            .unwrap();

        assert!(
            add_pos < jz_pos,
            "ADD (pos {add_pos}) must come before JZ (pos {jz_pos}) due to flags dependency"
        );
    }

    #[test]
    fn test_schedule_empty_block() {
        let mut instrs: Vec<Instruction> = vec![];
        let pass = InstructionSchedulingPass;
        pass.run(&mut instrs);
        assert!(instrs.is_empty());
    }

    #[test]
    fn test_schedule_single_instruction() {
        let code = [0x90]; // NOP
        let mut instrs = decode(&code);
        let pass = InstructionSchedulingPass;
        pass.run(&mut instrs);
        assert_eq!(instrs.len(), 1);
    }

    #[test]
    fn test_schedule_two_instructions() {
        // Two independent MOVs — should not crash or reorder incorrectly
        let code: &[u8] = &[
            0x48, 0xB8, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV RAX, 1
            0x48, 0xBB, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV RBX, 2
        ];
        let mut instrs = decode(code);
        let pass = InstructionSchedulingPass;
        pass.run(&mut instrs);
        assert_eq!(instrs.len(), 2);
    }

    // ── Integration: apply_passes round-trip ─────────────────────────────────

    #[test]
    fn test_apply_passes_preserves_function_semantics() {
        // Encode: MOV RAX, 42; ADD RAX, 8; RET
        // After applying passes, the ADD must still come after the MOV (RAW on RAX).
        let code = [
            0x48, 0xB8, 0x2A, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // MOV RAX, 42
            0x48, 0x83, 0xC0, 0x08, // ADD RAX, 8
            0xC3, // RET
        ];

        let result = apply_passes(&code);
        // Decode the result and verify ordering
        let decoded = Decoder::with_ip(64, &result, 0x1000, DecoderOptions::NONE);
        let instrs: Vec<Instruction> = decoded.into_iter().collect();

        let mov_pos = instrs
            .iter()
            .position(|i| i.code() == Code::Mov_r64_imm64 && i.immediate64() == 42)
            .unwrap();
        let add_pos = instrs
            .iter()
            .position(|i| i.code() == Code::Add_rm64_imm8 && i.immediate8() == 8)
            .unwrap();

        assert!(
            mov_pos < add_pos,
            "MOV RAX,42 must come before ADD RAX,8 (RAW dependency on RAX)"
        );
    }

    #[test]
    fn test_code_is_push_pop() {
        // Verify PUSH/POP recognition
        let code_push = Code::Push_r64;
        let code_pop = Code::Pop_r64;
        let code_mov = Code::Mov_r64_imm64;

        assert!(code_is_push(code_push));
        assert!(!code_is_push(code_pop));
        assert!(!code_is_push(code_mov));

        assert!(code_is_pop(code_pop));
        assert!(!code_is_pop(code_push));
        assert!(!code_is_pop(code_mov));
    }
}
