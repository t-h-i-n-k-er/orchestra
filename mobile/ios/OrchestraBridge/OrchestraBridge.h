// OrchestraBridge.h
// Public C header exposing the Orchestra agent's C ABI entry points.
//
// The Rust agent is compiled as a static library (libagent.a) and linked
// into the Xcode project. This header declares the extern "C" functions
// that the Swift side calls to manage the agent lifecycle.

#ifndef ORCHESTRA_BRIDGE_H
#define ORCHESTRA_BRIDGE_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Initialize the agent with an encrypted configuration blob.
 *
 * @param config_ptr  Pointer to encrypted config bytes.
 * @param config_len  Length of config in bytes.
 * @return 0 on success, -1 on failure.
 */
int orchestra_init(const uint8_t *config_ptr, size_t config_len);

/**
 * Start the agent's main command loop on a background thread.
 *
 * @return 0 on success, -1 if not initialized.
 */
int orchestra_start(void);

/**
 * Signal the agent to perform a graceful shutdown.
 */
void orchestra_stop(void);

/**
 * Check if the agent is currently running.
 *
 * @return 1 if running, 0 otherwise.
 */
int orchestra_is_running(void);

#ifdef __cplusplus
}
#endif

#endif // ORCHESTRA_BRIDGE_H