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

    fn fill_bytes(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&v[..chunk.len()]);
        }
    }
}

fn main() {
    // Generate a per-build 16-byte seed at compile time.  Every `cargo build`
    // produces a different STUB_SEED so the opaque dead-code stubs inserted by
    // the optimizer carry different values in each build — making the binary
    // fingerprint unique without requiring runtime entropy.
    //
    // M-40: Harvest entropy from multiple OS/process/thread sources and feed
    // a xoshiro256++ PRNG to avoid predictable build-time seeds.
    let seed: [u8; 16] = {
        let harvested = harvest_entropy();
        assert!(
            harvested.iter().any(|&b| b != 0),
            "harvest_entropy returned an all-zero seed; aborting build"
        );
        let mut rng = Xoshiro256PlusPlus::from_seed(harvested);
        let mut out = [0u8; 16];
        rng.fill_bytes(&mut out);
        out
    };

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest = Path::new(&out_dir).join("stub_seed.rs");
    std::fs::write(
        &dest,
        format!(
            "const STUB_SEED: [u8; 16] = [{}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}, {}];\n",
            seed[0], seed[1], seed[2], seed[3],
            seed[4], seed[5], seed[6], seed[7],
            seed[8], seed[9], seed[10], seed[11],
            seed[12], seed[13], seed[14], seed[15],
        ),
    )
    .unwrap();

    println!("cargo:rerun-if-changed=build.rs");
}
