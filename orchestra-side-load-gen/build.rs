use std::path::Path;

struct Sm64 {
    state: u64,
}

impl Sm64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }

    fn fill_bytes(&mut self, out: &mut [u8]) {
        let mut i = 0usize;
        while i < out.len() {
            let word = self.next_u64().to_le_bytes();
            let take = (out.len() - i).min(8);
            out[i..i + take].copy_from_slice(&word[..take]);
            i += take;
        }
    }
}

fn fmt_hex_array(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("0x{:02X}", b))
        .collect::<Vec<_>>()
        .join(", ")
}

fn main() {
    use std::time::{SystemTime, UNIX_EPOCH};

    // M-39: Generate 44 bytes of key material via SplitMix64:
    //   32-byte ChaCha20 key + 12-byte nonce.
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let pid = std::process::id() as u64;
    let seed = nanos ^ pid.wrapping_mul(0x9E3779B97F4A7C15);

    let mut sm = Sm64::new(seed);
    let mut material = [0u8; 44];
    sm.fill_bytes(&mut material);

    let mut key = [0u8; 32];
    key.copy_from_slice(&material[..32]);
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&material[32..44]);

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let dest = Path::new(&out_dir).join("side_key.rs");
    std::fs::write(
        &dest,
        format!(
            "const SIDE_CHACHA_KEY: [u8; 32] = [{}];\nconst SIDE_CHACHA_NONCE: [u8; 12] = [{}];\n",
            fmt_hex_array(&key),
            fmt_hex_array(&nonce),
        ),
    )
    .unwrap();

    println!("cargo:rerun-if-changed=build.rs");
}
