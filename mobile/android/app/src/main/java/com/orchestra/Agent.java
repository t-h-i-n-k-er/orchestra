package com.orchestra;

/**
 * JNI bridge for the Orchestra native agent library.
 *
 * <p>Loads liborchestra.so and exposes the native initialization, start, and stop functions.
 * All calls are forwarded to the Rust-side JNI bridge defined in agent/src/android/jni_bridge.rs.
 */
public class Agent {
    static {
        System.loadLibrary("orchestra");
    }

    /**
     * Initialize the agent with an encrypted configuration blob.
     *
     * @param configBytes encrypted agent.toml configuration bytes
     * @return 0 on success, -1 on failure
     */
    public static native int nativeInit(byte[] configBytes);

    /**
     * Start the agent's main command loop on a background thread.
     *
     * @return 0 on success, -1 if not initialized or already running
     */
    public static native int nativeStart();

    /**
     * Signal the agent to perform a graceful shutdown.
     */
    public static native void nativeStop();
}