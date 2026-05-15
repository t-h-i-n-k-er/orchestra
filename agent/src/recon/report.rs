//! # Reconnaissance Report Generation
//!
//! Combines all reconnaissance findings into a structured JSON report for
//! operator review and C2 transmission.
//!
//! ## Report Structure
//!
//! ```json
//! {
//!   "timestamp": "2024-01-15T12:00:00Z",
//!   "ad_recon": { ... },
//!   "attack_paths": [ ... ],
//!   "cloud_environment": { ... },
//!   "credential_attacks": { ... },
//!   "summary": {
//!     "total_users": 150,
//!     "kerberoastable": 12,
//!     "asrep_roastable": 3,
//!     "shortest_path_to_da": 2,
//!     "cloud_provider": "AWS"
//!   }
//! }
//! ```
//!
//! ## OPSEC
//!
//! The report is generated in-memory and transmitted via the C2 channel.
//! No files are written to disk.

use anyhow::Result;
use serde::{Deserialize, Serialize};
use tracing::info;

use super::ad_enum::AdReconData;
use super::attack_paths::AttackPath;
use super::cloud_fingerprint::{CloudEnvironment, CloudResources};
use super::credential_attacks::CredentialAttackSummary;

// ═══════════════════════════════════════════════════════════════════════════
// Data types
// ═══════════════════════════════════════════════════════════════════════════

/// Complete reconnaissance report.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconReport {
    /// Report generation timestamp (ISO 8601).
    pub timestamp: String,
    /// AD enumeration data (if available).
    pub ad_recon: Option<AdReconData>,
    /// Discovered attack paths to Domain Admins.
    pub attack_paths: Vec<AttackPath>,
    /// Cloud environment information.
    pub cloud_environment: Option<CloudEnvironment>,
    /// Cloud resources (if in a cloud environment).
    pub cloud_resources: Option<CloudResources>,
    /// Credential attack results.
    pub credential_attacks: Option<CredentialAttackSummary>,
    /// Executive summary of key findings.
    pub summary: ReconSummary,
}

/// Executive summary of reconnaissance findings.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReconSummary {
    /// Total number of enumerated users.
    pub total_users: usize,
    /// Number of disabled accounts.
    pub disabled_users: usize,
    /// Number of Kerberoastable accounts (have SPNs).
    pub kerberoastable_accounts: usize,
    /// Number of AS-REP Roastable accounts.
    pub asrep_roastable_accounts: usize,
    /// Number of privileged groups.
    pub privileged_groups: usize,
    /// Number of computer accounts.
    pub total_computers: usize,
    /// Number of domain trusts.
    pub total_trusts: usize,
    /// Number of delegation configurations.
    pub total_delegations: usize,
    /// Number of unconstrained delegation accounts.
    pub unconstrained_delegations: usize,
    /// Number of AD CS templates.
    pub adcs_templates: usize,
    /// Shortest attack path length to Domain Admins (0 = already DA).
    pub shortest_path_to_da: Option<usize>,
    /// Number of attack paths found.
    pub total_attack_paths: usize,
    /// Detected cloud provider (if any).
    pub cloud_provider: String,
    /// Whether IMDS is accessible.
    pub imds_accessible: bool,
    /// Number of extracted Kerberoast hashes.
    pub kerberoast_hashes_extracted: usize,
    /// Number of extracted AS-REP hashes.
    pub asrep_hashes_extracted: usize,
    /// Domain lockout threshold.
    pub lockout_threshold: u32,
    /// Domain functional level.
    pub domain_functional_level: String,
    /// Key risk indicators.
    pub risk_indicators: Vec<String>,
}

// ═══════════════════════════════════════════════════════════════════════════
// Report generation
// ═══════════════════════════════════════════════════════════════════════════

/// Generate a complete reconnaissance report from all available data.
///
/// Combines AD enumeration, attack paths, cloud fingerprinting, and
/// credential attack results into a single JSON-serializable report.
///
/// # Arguments
///
/// * `ad_data` - AD enumeration data (None if enumeration failed).
/// * `attack_paths` - Discovered attack paths to DA.
/// * `cloud_env` - Cloud environment info (None if not in cloud).
/// * `cloud_res` - Cloud resources (None if not enumerated).
/// * `cred_attacks` - Credential attack results (None if not run).
///
/// # Returns
///
/// A [`ReconReport`] that can be serialized to JSON.
pub fn generate_recon_report(
    ad_data: Option<AdReconData>,
    attack_paths: Vec<AttackPath>,
    cloud_env: Option<CloudEnvironment>,
    cloud_res: Option<CloudResources>,
    cred_attacks: Option<CredentialAttackSummary>,
) -> ReconReport {
    let timestamp = chrono_now_iso();

    // Build summary from available data
    let summary = build_summary(&ad_data, &attack_paths, &cloud_env, &cred_attacks);

    info!(
        "Recon report: {} users, {} attack paths, cloud={}, {} kerberoast hashes",
        summary.total_users,
        summary.total_attack_paths,
        summary.cloud_provider,
        summary.kerberoast_hashes_extracted,
    );

    ReconReport {
        timestamp,
        ad_recon: ad_data,
        attack_paths,
        cloud_environment: cloud_env,
        cloud_resources: cloud_res,
        credential_attacks: cred_attacks,
        summary,
    }
}

/// Generate the executive summary.
fn build_summary(
    ad_data: &Option<AdReconData>,
    attack_paths: &[AttackPath],
    cloud_env: &Option<CloudEnvironment>,
    cred_attacks: &Option<CredentialAttackSummary>,
) -> ReconSummary {
    let mut risk_indicators = Vec::new();

    let (
        total_users,
        disabled_users,
        kerberoastable,
        asrep_roastable,
        privileged_groups,
        total_computers,
        total_trusts,
        total_delegations,
        unconstrained,
        adcs_templates,
        lockout_threshold,
        domain_functional_level,
    ) = if let Some(data) = ad_data {
        let kerb = data.users.iter().filter(|u| u.is_kerberoastable).count();
        let asrep = data.users.iter().filter(|u| u.is_asrep_roastable).count();
        let priv_groups = data.groups.iter().filter(|g| g.is_privileged).count();
        let unc = data
            .delegations
            .iter()
            .filter(|d| d.delegation_type == "unconstrained")
            .count();

        if kerb > 0 {
            risk_indicators.push(format!("{} Kerberoastable accounts found", kerb));
        }
        if asrep > 0 {
            risk_indicators.push(format!(
                "{} AS-REP Roastable accounts (DONT_REQUIRE_PREAUTH)",
                asrep
            ));
        }
        if unc > 0 {
            risk_indicators.push(format!("{} accounts with unconstrained delegation", unc));
        }
        if !data.trusts.is_empty() {
            risk_indicators.push(format!("{} domain trust relationships", data.trusts.len()));
        }

        (
            data.users.len(),
            data.users.iter().filter(|u| u.is_disabled).count(),
            kerb,
            asrep,
            priv_groups,
            data.computers.len(),
            data.trusts.len(),
            data.delegations.len(),
            unc,
            data.adcs_templates.len(),
            data.lockout_threshold,
            data.domain_functional_level.clone(),
        )
    } else {
        (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, "N/A".to_string())
    };

    let shortest_path = attack_paths.first().map(|p| p.total_hops);
    let total_attack_paths = attack_paths.len();

    if !attack_paths.is_empty() {
        if let Some(hops) = shortest_path {
            if hops == 0 {
                risk_indicators.insert(0, "CURRENT USER IS DOMAIN ADMIN".to_string());
            } else {
                risk_indicators.insert(0, format!("Shortest path to DA: {} hops", hops));
            }
        }
    }

    let cloud_provider = cloud_env
        .as_ref()
        .map(|e| e.provider.to_string())
        .unwrap_or_else(|| "Unknown".to_string());

    let imds_accessible = cloud_env
        .as_ref()
        .map(|e| e.imds_accessible)
        .unwrap_or(false);

    if imds_accessible {
        risk_indicators.push(format!("IMDS accessible in {} environment", cloud_provider));
    }

    let (kerberoast_hashes, asrep_hashes) = cred_attacks
        .as_ref()
        .map(|ca| {
            (
                ca.kerberoast_results.iter().filter(|r| r.success).count(),
                ca.asrep_roast_results.iter().filter(|r| r.success).count(),
            )
        })
        .unwrap_or((0, 0));

    if kerberoast_hashes > 0 {
        risk_indicators.push(format!("{} Kerberoast hashes extracted", kerberoast_hashes));
    }
    if asrep_hashes > 0 {
        risk_indicators.push(format!("{} AS-REP hashes extracted", asrep_hashes));
    }

    ReconSummary {
        total_users,
        disabled_users,
        kerberoastable_accounts: kerberoastable,
        asrep_roastable_accounts: asrep_roastable,
        privileged_groups,
        total_computers,
        total_trusts,
        total_delegations,
        unconstrained_delegations: unconstrained,
        adcs_templates,
        shortest_path_to_da: shortest_path,
        total_attack_paths,
        cloud_provider,
        imds_accessible,
        kerberoast_hashes_extracted: kerberoast_hashes,
        asrep_hashes_extracted: asrep_hashes,
        lockout_threshold,
        domain_functional_level,
        risk_indicators,
    }
}

/// Serialize the report to JSON.
pub fn serialize_report(report: &ReconReport) -> Result<Vec<u8>> {
    let json = serde_json::to_vec_pretty(report)?;
    Ok(json)
}

/// Serialize the report to a JSON string.
pub fn serialize_report_string(report: &ReconReport) -> Result<String> {
    let json = serde_json::to_string_pretty(report)?;
    Ok(json)
}

/// Deserialize a report from JSON bytes.
pub fn deserialize_report(data: &[u8]) -> Result<ReconReport> {
    let report: ReconReport = serde_json::from_slice(data)?;
    Ok(report)
}

/// Get current timestamp as ISO 8601.
fn chrono_now_iso() -> String {
    let duration = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    let days = secs / 86400;
    let time_of_day = secs % 86400;
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    let (year, month, day) = days_to_ymd(days as i32);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        year, month, day, hours, minutes, seconds
    )
}

/// Approximate year/month/day from days since Unix epoch.
fn days_to_ymd(mut days: i32) -> (i32, u32, u32) {
    let year = 1970 + days / 365;
    days %= 365;
    let month_days = [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut month = 0;
    for (i, &md) in month_days.iter().enumerate() {
        if days < md {
            month = i;
            break;
        }
        days -= md;
    }
    (year, month as u32 + 1, (days + 1) as u32)
}

// ═══════════════════════════════════════════════════════════════════════════
// Tests
// ═══════════════════════════════════════════════════════════════════════════

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recon::ad_enum::*;
    use crate::recon::attack_paths::*;
    use crate::recon::cloud_fingerprint::*;
    use crate::recon::credential_attacks::*;

    fn make_test_ad_data() -> AdReconData {
        AdReconData {
            domain: "test.local".to_string(),
            domain_netbios: "TEST".to_string(),
            dc_hostname: "DC01".to_string(),
            domain_functional_level: "Windows Server 2019".to_string(),
            domain_sid: "S-1-5-21-...".to_string(),
            users: vec![
                AdUser {
                    sam_account_name: "admin".to_string(),
                    display_name: "Admin".to_string(),
                    distinguished_name: "CN=admin,CN=Users,DC=test,DC=local".to_string(),
                    member_of: vec!["CN=Domain Admins,CN=Users,DC=test,DC=local".to_string()],
                    user_account_control: 0x200,
                    service_principal_names: vec![],
                    description: String::new(),
                    last_logon: String::new(),
                    pwd_last_set: String::new(),
                    admin_count: true,
                    is_asrep_roastable: false,
                    is_kerberoastable: false,
                    is_disabled: false,
                    is_password_never_expires: true,
                    is_unconstrained_delegation: false,
                },
                AdUser {
                    sam_account_name: "svc_mssql".to_string(),
                    display_name: "MSSQL".to_string(),
                    distinguished_name: "CN=svc_mssql,DC=test,DC=local".to_string(),
                    member_of: vec![],
                    user_account_control: 0x10200,
                    service_principal_names: vec!["MSSQLSVC/db01:1433".to_string()],
                    description: String::new(),
                    last_logon: String::new(),
                    pwd_last_set: String::new(),
                    admin_count: false,
                    is_asrep_roastable: false,
                    is_kerberoastable: true,
                    is_disabled: false,
                    is_password_never_expires: true,
                    is_unconstrained_delegation: false,
                },
            ],
            groups: vec![AdGroup {
                cn: "Domain Admins".to_string(),
                distinguished_name: "CN=Domain Admins,CN=Users,DC=test,DC=local".to_string(),
                members: vec!["CN=admin,CN=Users,DC=test,DC=local".to_string()],
                member_of: vec![],
                group_type: -2147483646,
                description: String::new(),
                is_privileged: true,
            }],
            computers: vec![AdComputer {
                cn: "WS01".to_string(),
                distinguished_name: "CN=WS01,DC=test,DC=local".to_string(),
                operating_system: "Windows 10".to_string(),
                dns_host_name: "ws01.test.local".to_string(),
                service_principal_names: vec![],
                last_logon: String::new(),
                is_enabled: true,
            }],
            gpos: vec![],
            trusts: vec![],
            spns: vec![AdSpn {
                sam_account_name: "svc_mssql".to_string(),
                distinguished_name: "CN=svc_mssql,DC=test,DC=local".to_string(),
                service_principal_names: vec!["MSSQLSVC/db01:1433".to_string()],
            }],
            delegations: vec![],
            adcs_templates: vec![],
            lockout_threshold: 5,
            lockout_duration_minutes: 30,
            timestamp: "2024-01-15T12:00:00Z".to_string(),
        }
    }

    #[test]
    fn test_generate_report_with_ad_data() {
        let ad_data = make_test_ad_data();
        let report = generate_recon_report(Some(ad_data), vec![], None, None, None);

        assert!(report.ad_recon.is_some());
        assert_eq!(report.summary.total_users, 2);
        assert_eq!(report.summary.kerberoastable_accounts, 1);
        assert_eq!(report.summary.total_computers, 1);
        assert!(!report.timestamp.is_empty());
    }

    #[test]
    fn test_generate_report_empty() {
        let report = generate_recon_report(None, vec![], None, None, None);

        assert!(report.ad_recon.is_none());
        assert_eq!(report.summary.total_users, 0);
        assert_eq!(report.summary.cloud_provider, "Unknown");
    }

    #[test]
    fn test_report_with_attack_paths() {
        let ad_data = make_test_ad_data();
        let paths = vec![AttackPath {
            steps: vec![AttackStep {
                source: "CN=jdoe,DC=test,DC=local".to_string(),
                target: "CN=Domain Admins,CN=Users,DC=test,DC=local".to_string(),
                edge_type: "MemberOf".to_string(),
                description: "jdoe is in Domain Admins".to_string(),
            }],
            total_hops: 1,
            risk_level: RiskLevel::High,
            summary: "MemberOf → DA".to_string(),
        }];

        let report = generate_recon_report(Some(ad_data), paths, None, None, None);

        assert_eq!(report.summary.total_attack_paths, 1);
        assert_eq!(report.summary.shortest_path_to_da, Some(1));
    }

    #[test]
    fn test_report_with_cloud() {
        let cloud_env = CloudEnvironment {
            provider: CloudProvider::Aws,
            instance_id: "i-123".to_string(),
            instance_type: "t3.medium".to_string(),
            region: "us-east-1".to_string(),
            availability_zone: "us-east-1a".to_string(),
            network_id: "vpc-123".to_string(),
            subnet_id: "subnet-123".to_string(),
            iam_role: "ec2-role".to_string(),
            imds_accessible: true,
            imds_raw: String::new(),
        };

        let report = generate_recon_report(None, vec![], Some(cloud_env), None, None);

        assert_eq!(report.summary.cloud_provider, "AWS");
        assert!(report.summary.imds_accessible);
    }

    #[test]
    fn test_serialize_report() {
        let report = generate_recon_report(None, vec![], None, None, None);

        let bytes = serialize_report(&report).unwrap();
        assert!(!bytes.is_empty());

        let json_str = String::from_utf8(bytes).unwrap();
        assert!(json_str.contains("timestamp"));
        assert!(json_str.contains("summary"));
    }

    #[test]
    fn test_deserialize_report() {
        let report = generate_recon_report(None, vec![], None, None, None);

        let bytes = serialize_report(&report).unwrap();
        let de = deserialize_report(&bytes).unwrap();

        assert_eq!(de.summary.total_users, 0);
        assert_eq!(de.summary.cloud_provider, "Unknown");
    }

    #[test]
    fn test_risk_indicators() {
        let ad_data = make_test_ad_data();
        let report = generate_recon_report(Some(ad_data), vec![], None, None, None);

        assert!(!report.summary.risk_indicators.is_empty());
        assert!(report
            .summary
            .risk_indicators
            .iter()
            .any(|ri| ri.contains("Kerberoastable")));
    }

    #[test]
    fn test_report_json_structure() {
        let report = generate_recon_report(None, vec![], None, None, None);

        let json = serialize_report_string(&report).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert!(parsed.get("timestamp").is_some());
        assert!(parsed.get("ad_recon").is_some());
        assert!(parsed.get("attack_paths").is_some());
        assert!(parsed.get("cloud_environment").is_some());
        assert!(parsed.get("credential_attacks").is_some());
        assert!(parsed.get("summary").is_some());
    }

    #[test]
    fn test_days_to_ymd_report() {
        let (y, m, d) = days_to_ymd(0);
        assert_eq!(y, 1970);
        assert_eq!(m, 1);
        assert_eq!(d, 1);
    }

    #[test]
    fn test_chrono_now_iso_report() {
        let ts = chrono_now_iso();
        assert!(ts.contains('T'));
        assert!(ts.ends_with('Z'));
        assert_eq!(ts.len(), 20); // YYYY-MM-DDTHH:MM:SSZ
    }

    #[test]
    fn test_recon_summary_serde() {
        let summary = ReconSummary {
            total_users: 100,
            disabled_users: 10,
            kerberoastable_accounts: 5,
            asrep_roastable_accounts: 2,
            privileged_groups: 3,
            total_computers: 50,
            total_trusts: 1,
            total_delegations: 4,
            unconstrained_delegations: 1,
            adcs_templates: 2,
            shortest_path_to_da: Some(3),
            total_attack_paths: 5,
            cloud_provider: "Azure".to_string(),
            imds_accessible: true,
            kerberoast_hashes_extracted: 5,
            asrep_hashes_extracted: 2,
            lockout_threshold: 5,
            domain_functional_level: "Windows Server 2019".to_string(),
            risk_indicators: vec!["5 Kerberoastable accounts found".to_string()],
        };

        let json = serde_json::to_string(&summary).unwrap();
        let de: ReconSummary = serde_json::from_str(&json).unwrap();
        assert_eq!(de.total_users, 100);
        assert_eq!(de.shortest_path_to_da, Some(3));
    }
}
