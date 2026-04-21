//! Standalone agent binary.
//!
//! When built with the `outbound-c` feature the agent dials the Orchestra
//! Control Center automatically (address baked in at build time or read from
//! the `ORCHESTRA_C` environment variable) and reconnects on disconnection.
//!
//! Without `outbound-c` the binary exits with a clear diagnostic; the normal
//! deployment path in that case is the [`launcher`] crate, which downloads and
//! executes the agent library in-memory after the console makes the first
//! connection.

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run().await
}

#[cfg(feature = "outbound-c")]
async fn run() -> anyhow::Result<()> {
    tracing_subscriber::fmt().init();
    agent::outbound::run_forever().await
}

#[cfg(not(feature = "outbound-c"))]
async fn run() -> anyhow::Result<()> {
    anyhow::bail!(
        "This agent-standalone binary was built without the `outbound-c` feature. \
         Enable `outbound-c` at compile time (the Builder does this automatically \
         when the feature is included in the profile) so the agent knows where to connect."
    )
}
