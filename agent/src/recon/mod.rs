//! # Automated Internal Reconnaissance and Target Profiling
//!
//! Comprehensive Active Directory enumeration, automated attack path discovery,
//! cloud environment fingerprinting, and credential attack automation for
//! red-team operations in domain-joined Windows environments.
//!
//! ## Module Structure
//!
//! - **`ad_enum`** — Active Directory enumeration via LDAP: users, groups,
//!   computers, trusts, SPNs, delegations, and AD CS certificate templates.
//!   Uses wldap32.dll resolved via pe_resolve — no IAT entries.
//!
//! - **`attack_paths`** — Graph-based attack path discovery: builds a directed
//!   relationship graph from AD data and performs BFS from the current context
//!   to Domain Admins. Identifies the shortest exploitation paths.
//!
//! - **`cloud_fingerprint`** — Cloud environment detection and resource
//!   enumeration: probes AWS, Azure, and GCP metadata endpoints; enumerates
//!   cloud resources using stolen temporary credentials.
//!
//! - **`credential_attacks`** — Automated credential attacks: Kerberoasting
//!   (SPN → TGS → hashcat hash), AS-REP Roasting (DONT_REQUIRE_PREAUTH →
//!   AS-REQ → hashcat hash), password spraying (with lockout threshold
//!   awareness), and credential stuffing.
//!
//! - **`report`** — Recon report generation: produces a comprehensive JSON
//!   report of all findings for transmission to the C2 server.
//!
//! ## OPSEC Considerations
//!
//! - All LDAP queries use the agent's current security context (no additional
//!   authentication required — the machine account or user token suffices).
//! - Kerberoasting works as any domain user; no elevated privileges needed.
//! - Password spraying respects account lockout thresholds and includes
//!   configurable inter-attempt delays.
//! - LDAP connection uses port 389 (LDAP, not LDAPS) for broader compatibility,
//!   but the bind uses SSPI Negotiate (GSSAPI/Kerberos).
//!
//! ## Feature Gate
//!
//! Windows-only, gated by `recon` feature flag (implies `direct-syscalls`).

pub mod ad_enum;
pub mod attack_paths;
pub mod cloud_fingerprint;
pub mod credential_attacks;
pub mod report;
