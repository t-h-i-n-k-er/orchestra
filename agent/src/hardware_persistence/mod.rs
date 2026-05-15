//! Hardware-level persistence and attack capabilities.
//!
//! **⚠️ AUTHORIZED RED TEAM USE ONLY ⚠️**
//!
//! This module provides physical-access-tier capabilities that survive all
//! OS-level remediation.  Techniques require the operator to be physically
//! present at the target machine (or for the target to already have a DMA-
//! capable device connected).
//!
//! # Sub-modules
//!
//! - **[`thunderbolt_dma`]** — Thunderbolt controller detection, DMA
//!   vulnerability assessment, DMA payload generation, and physical memory
//!   access via DMA or BYOVD driver.
//! - **[`boot_persistence`]** — Boot-sector / VBR persistence for Legacy
//!   BIOS systems, UEFI boot driver persistence, and boot-level artifact
//!   detection and removal.
//!
//! # Safety Guarantees
//!
//! - All disk/sector writes are preceded by a backup of the original data
//! - Every write is verified by reading back and comparing
//! - Secure Boot status is checked before attempting boot modifications
//! - Operations that would brick the system (e.g., corrupting the MBR)
//!   are refused unless explicitly forced
//! - Physical access requirements are documented per technique
//!
//! # Feature Flag
//!
//! Gated by `hardware-persistence` feature flag.  Cross-platform (Linux
//! and Windows).

#![cfg(feature = "hardware-persistence")]

pub mod boot_persistence;
pub mod thunderbolt_dma;

// Re-export primary types for convenience.
pub use boot_persistence::{
    check_bios_uefi_mode, detect_existing_persistence, install_uefi_boot_persistence,
    install_vbr_persistence, remove_persistence, BootMode, PersistenceArtifact,
};
pub use thunderbolt_dma::{
    check_dma_vulnerability, detect_thunderbolt_controller, dma_read_physical, prepare_dma_payload,
    DmaPayload, DmaVulnerability, ThunderboltInfo,
};
