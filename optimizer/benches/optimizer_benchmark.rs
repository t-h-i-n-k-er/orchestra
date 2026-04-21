use criterion::{criterion_group, criterion_main, Criterion};
use optimizer::hot_function;

fn original_benchmark(c: &mut Criterion) {
    c.bench_function("hot_function_original", |b| b.iter(hot_function));
}

fn optimized_benchmark(c: &mut Criterion) {
    let optimizer = optimizer::Optimizer::new();
    let test_vector: Vec<i32> = vec![0; 1];
    let _ = optimizer.optimize_safely(hot_function as fn() -> i32, &test_vector);
    c.bench_function("hot_function_optimized", |b| b.iter(hot_function));
}

criterion_group!(benches, original_benchmark, optimized_benchmark);
criterion_main!(benches);
