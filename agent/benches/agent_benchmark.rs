//! Throughput micro-benchmarks for the Orchestra protocol layer.
//!
//! Run with: `cargo bench -p agent --bench agent_benchmark`
//!
//! These benchmarks measure:
//!   1. JSON encode + AES-256-GCM encrypt for a `Ping` task request.
//!   2. AES-256-GCM decrypt + JSON decode of the same payload.
//!   3. Encrypting a 100 MiB blob (representative of a large file transfer).

use common::{Command, CryptoSession, Message};
use criterion::{criterion_group, criterion_main, Criterion, Throughput};
use std::hint::black_box;

fn bench_message_encode_encrypt(c: &mut Criterion) {
    let session = CryptoSession::from_shared_secret(b"benchmark-shared-secret");
    let msg = Message::TaskRequest {
        task_id: "00000000-0000-0000-0000-000000000000".into(),
        command: Command::Ping,
    };
    let bytes = serde_json::to_vec(&msg).unwrap();

    c.bench_function("encode+encrypt ping", |b| {
        b.iter(|| {
            let plaintext = serde_json::to_vec(black_box(&msg)).unwrap();
            let _ct = session.encrypt(black_box(&plaintext));
        })
    });

    c.bench_function("decrypt+decode ping", |b| {
        let ct = session.encrypt(&bytes);
        b.iter(|| {
            let pt = session.decrypt(black_box(&ct)).unwrap();
            let _m: Message = serde_json::from_slice(&pt).unwrap();
        })
    });
}

fn bench_large_payload_encrypt(c: &mut Criterion) {
    let session = CryptoSession::from_shared_secret(b"benchmark-shared-secret");
    let payload = vec![0u8; 100 * 1024 * 1024]; // 100 MiB

    let mut group = c.benchmark_group("large-payload");
    group.sample_size(10); // 100 MiB encryption is slow; reduce sample count
    group.throughput(Throughput::Bytes(payload.len() as u64));
    group.bench_function("encrypt 100MiB", |b| {
        b.iter(|| {
            let _ct = session.encrypt(black_box(&payload));
        })
    });
    group.finish();
}

criterion_group!(benches, bench_message_encode_encrypt, bench_large_payload_encrypt);
criterion_main!(benches);
