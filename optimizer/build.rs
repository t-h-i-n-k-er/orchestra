use std::path::Path;

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
}

fn main() {
    // Only generate stub_seed.rs when the `diversification` feature is enabled.
    // The feature flag is communicated via the cargo:rustc-cfg printed by the
    // [features] section in Cargo.toml, but build scripts cannot inspect
    // features directly — instead we always generate the file (it's tiny) and
    // let the `#[cfg(feature = "diversification")]` gate on the `include!`
    // side decide whether it is actually compiled.

    // Support a reproducible-build override: if OPTIMIZER_STUB_SEED is set,
    // use its value (a hex-encoded u64) instead of harvesting fresh entropy.
    println!("cargo:rerun-if-env-changed=OPTIMIZER_STUB_SEED");
    println!("cargo:rerun-if-changed=build.rs");

    let seed_value: u64 = if let Ok(hex_str) = std::env::var("OPTIMIZER_STUB_SEED") {
        u64::from_str_radix(hex_str.trim(), 16)
            .expect("OPTIMIZER_STUB_SEED must be a valid hex-encoded u64")
    } else {
        let harvested = harvest_entropy();
        assert!(
            harvested.iter().any(|&b| b != 0),
            "harvest_entropy returned an all-zero seed; aborting build"
        );
        let mut rng = Xoshiro256PlusPlus::from_seed(harvested);
        rng.next_u64()
    };

    let seed_bytes = seed_value.to_le_bytes();

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest = Path::new(&out_dir).join("stub_seed.rs");
    std::fs::write(
        &dest,
        format!(
            "pub const STUB_SEED: [u8; 8] = [{}, {}, {}, {}, {}, {}, {}, {}];\n",
            seed_bytes[0], seed_bytes[1], seed_bytes[2], seed_bytes[3],
            seed_bytes[4], seed_bytes[5], seed_bytes[6], seed_bytes[7],
        ),
    )
    .unwrap();
}
