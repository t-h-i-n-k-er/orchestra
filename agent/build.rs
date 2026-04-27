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

fn main() {
    println!("cargo:rerun-if-env-changed=ORCHESTRA_KEY");
    println!("cargo:rerun-if-env-changed=ORCHESTRA_NONCE");

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
}
