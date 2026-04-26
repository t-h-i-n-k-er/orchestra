use criterion::{black_box, criterion_group, criterion_main, Criterion};

/// Minimal x86-64 code sequence: `mov eax, 1; ret` — valid input for the optimizer.
const SYNTHETIC_CODE: &[u8] = &[0xB8, 0x01, 0x00, 0x00, 0x00, 0xC3];

fn bench_apply_passes(c: &mut Criterion) {
    c.bench_function("apply_passes synthetic", |b| {
        b.iter(|| optimizer::apply_passes(black_box(SYNTHETIC_CODE)))
    });
}

fn bench_apply_passes_larger(c: &mut Criterion) {
    // A small block with a conditional jump: `xor eax,eax; test eax,eax; jz +2; nop; ret`
    let code: &[u8] = &[
        0x31, 0xC0, // xor  eax, eax
        0x85, 0xC0, // test eax, eax
        0x74, 0x01, // jz   +1  (skip nop)
        0x90, // nop
        0xC3, // ret
    ];
    c.bench_function("apply_passes branch block", |b| {
        b.iter(|| optimizer::apply_passes(black_box(code)))
    });
}

criterion_group!(benches, bench_apply_passes, bench_apply_passes_larger);
criterion_main!(benches);
