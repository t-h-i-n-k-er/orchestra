// OrchestraBridge.c
// C bridge calling the Rust agent's extern "C" functions.
//
// This file is a thin shim — the actual implementations live in the Rust
// agent crate, compiled as a static library and linked into the target.
// The Rust side must expose:
//   #[no_mangle] pub extern "C" fn orchestra_init(config_ptr: *const u8, config_len: usize) -> i32
//   #[no_mangle] pub extern "C" fn orchestra_start() -> i32
//   #[no_mangle] pub extern "C" fn orchestra_stop()
//   #[no_mangle] pub extern "C" fn orchestra_is_running() -> i32

#include <stdio.h>
#include "OrchestraBridge.h"

// Weak symbols — the linker resolves these from the Rust static library.
// If the Rust library is not linked, calls will return -1 / 0 / no-op.

__attribute__((weak)) int orchestra_init(const uint8_t *config_ptr, size_t config_len) {
    (void)config_ptr;
    (void)config_len;
    fprintf(stderr, "orchestra: WEAK STUB orchestra_init called — "
                    "Rust static library (libagent.a) is not linked.\n");
    return -1;
}

__attribute__((weak)) int orchestra_start(void) {
    fprintf(stderr, "orchestra: WEAK STUB orchestra_start called — "
                    "Rust static library (libagent.a) is not linked.\n");
    return -1;
}

__attribute__((weak)) void orchestra_stop(void) {
    fprintf(stderr, "orchestra: WEAK STUB orchestra_stop called — "
                    "Rust static library (libagent.a) is not linked.\n");
}

__attribute__((weak)) int orchestra_is_running(void) {
    fprintf(stderr, "orchestra: WEAK STUB orchestra_is_running called — "
                    "Rust static library (libagent.a) is not linked.\n");
    return 0;
}
