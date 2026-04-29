use code_transform_macro as code_transform;

#[code_transform::transform]
fn arithmetic_mix(a: u64, b: u64, c: u64) -> u64 {
    (a + b) ^ c
}

#[test]
fn transformed_function_executes() {
    let got = arithmetic_mix(0x10, 0x20, 0x33);
    let want = (0x10u64 + 0x20u64) ^ 0x33u64;
    assert_eq!(got, want);
}
