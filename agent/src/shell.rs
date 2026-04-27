//! Interactive shell session management.
//!
//! ## Non-blocking output reads
//!
//! `try_read_output` must never block the caller — the agent's command
//! dispatcher waits for it synchronously inside an async task. The
//! original implementation called `read_to_end` on the PTY master,
//! which blocks until EOF (i.e. until the child exits) and froze the
//! worker thread.
//!
//! The fix: a dedicated reader thread continuously performs small
//! blocking `read()` calls on the PTY master into a shared buffer.
//! `try_read_output` simply drains the buffer (under a short-lived
//! mutex) and returns whatever is currently available, returning an
//! empty `Vec` when no new bytes have arrived. The writer stays in
//! ordinary blocking mode because input writes are small (a single
//! command line) and well-behaved.

use anyhow::Result;
use portable_pty::{ChildKiller, CommandBuilder, NativePtySystem, PtySize, PtySystem};
use std::io::{Read, Write};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

const READ_CHUNK: usize = 4096;

pub struct ShellSession {
    writer: Box<dyn Write + Send>,
    buffer: Arc<Mutex<Vec<u8>>>,
    child_killer: Option<Box<dyn ChildKiller + Send + Sync>>,
    reader_thread: Option<JoinHandle<()>>,
    is_running: Arc<std::sync::atomic::AtomicBool>,
}

impl ShellSession {
    pub fn new() -> Result<Self> {
        let pty_system = NativePtySystem::default();
        let pair = pty_system.openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })?;

        let cmd = if cfg!(windows) {
            CommandBuilder::new("cmd.exe")
        } else {
            let shell_path = std::env::var("SHELL")
                .ok()
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| "/bin/sh".to_string());
            log::info!("Shell session started with: {}", shell_path);
            CommandBuilder::new(shell_path)
        };

        let child = pair.slave.spawn_command(cmd)?;
        // SAFETY: The child has been spawned with the slave end attached; this
        // constructor no longer needs its local slave handle.
        // Dropping it immediately narrows the lifetime and prevents accidental
        // future use of `pair.slave` in refactors.
        drop(pair.slave);

        let child_killer = Some(child.clone_killer());

        // SAFETY / ORDERING INVARIANT (DO NOT REORDER):
        // `take_writer()` and `try_clone_reader()` MUST run before
        // `drop(pair.master)`. Dropping the master closes that PTY endpoint,
        // and any subsequent attempt to take/clone streams from `pair.master`
        // can panic or fail unexpectedly.
        //
        // Required order:
        //   1) `take_writer()`
        //   2) `try_clone_reader()`
        //   3) `drop(pair.master)`
        let writer = pair.master.take_writer()?;
        let mut reader = pair.master.try_clone_reader()?;

        // Drop the remaining setup handle so the PTY closes cleanly when
        // the child exits, allowing the reader thread to observe EOF.
        let is_running = Arc::new(std::sync::atomic::AtomicBool::new(true));

        // SAFETY: Writer/reader were extracted above in the required order,
        // so dropping this leftover setup handle is now correct.
        drop(pair.master);

        let buffer: Arc<Mutex<Vec<u8>>> = Arc::new(Mutex::new(Vec::new()));
        let buf_clone = buffer.clone();
        let running_clone = is_running.clone();
        let reader_thread = std::thread::Builder::new()
            .name("orchestra-pty-reader".into())
            .spawn(move || {
                let mut chunk = [0u8; READ_CHUNK];
                loop {
                    if !running_clone.load(std::sync::atomic::Ordering::Relaxed) {
                        break;
                    }
                    match reader.read(&mut chunk) {
                        Ok(0) => break, // EOF
                        Ok(n) => {
                            if let Ok(mut b) = buf_clone.lock() {
                                b.extend_from_slice(&chunk[..n]);
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                        Err(_) => break,
                    }
                }
            })?;

        Ok(Self {
            writer,
            buffer,
            child_killer,
            reader_thread: Some(reader_thread),
            is_running,
        })
    }

    pub fn write_input(&mut self, data: &[u8]) -> Result<()> {
        self.writer.write_all(data)?;
        self.writer.flush()?;
        Ok(())
    }

    /// Drain whatever output the reader thread has accumulated so far.
    /// Never blocks. Returns an empty `Vec` when nothing is available.
    pub fn try_read_output(&mut self) -> Vec<u8> {
        match self.buffer.lock() {
            Ok(mut buf) => std::mem::take(&mut *buf),
            Err(_) => Vec::new(),
        }
    }
}

impl Drop for ShellSession {
    fn drop(&mut self) {
        if let Some(mut killer) = self.child_killer.take() {
            killer.kill().ok();
        }
        if let Some(handle) = self.reader_thread.take() {
            self.is_running
                .store(false, std::sync::atomic::Ordering::Relaxed);
            let (tx, rx) = std::sync::mpsc::channel();
            crate::evasion::spawn_hidden_thread(move || {
                let _ = handle.join();
                let _ = tx.send(());
            });
            // Give the thread a little bit of time to tidy up
            let _ = rx.recv_timeout(std::time::Duration::from_millis(500));
        }
    }
}

#[cfg(test)]
#[cfg(target_os = "linux")]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    fn read_until_contains(session: &mut ShellSession, needle: &str, timeout: Duration) -> Vec<u8> {
        let mut accumulated: Vec<u8> = Vec::new();
        let start = Instant::now();
        while start.elapsed() < timeout {
            let chunk = session.try_read_output();
            if !chunk.is_empty() {
                accumulated.extend_from_slice(&chunk);
                if String::from_utf8_lossy(&accumulated).contains(needle) {
                    return accumulated;
                }
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        accumulated
    }

    #[test]
    fn try_read_output_does_not_block() {
        let mut session = ShellSession::new().unwrap();
        let start = Instant::now();
        let _ = session.try_read_output();
        assert!(
            start.elapsed() < Duration::from_millis(200),
            "try_read_output should return immediately"
        );
    }

    #[test]
    fn echo_round_trip_in_chunks() {
        let mut session = ShellSession::new().unwrap();
        // Wait briefly for the shell to be ready, then send the command.
        std::thread::sleep(Duration::from_millis(100));
        session.write_input(b"echo hello\n").unwrap();

        let output = read_until_contains(&mut session, "hello", Duration::from_secs(5));
        let text = String::from_utf8_lossy(&output);
        assert!(
            text.contains("hello"),
            "expected 'hello' in output, got: {text:?}"
        );
    }
}
