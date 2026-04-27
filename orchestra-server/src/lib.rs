//! Orchestra Control Center
//!
//! Self-hosted management plane that fronts a fleet of Orchestra agents.
//! Agents connect over an AES-encrypted TCP socket (reusing
//! [`common::CryptoSession`] / [`common::transport::TcpTransport`]); operators
//! interact through an HTTPS dashboard authenticated with a bearer token.
//!
//! See `docs/C_SERVER.md` for the deployment guide.

pub mod agent_link;
pub mod api;
pub mod audit;
pub mod auth;
pub mod build_handler;
pub mod config;
pub mod doh_listener;
pub mod state;
pub mod tls;
