//! Client-side device fingerprinting for non-browser environments.
//!
//! Collects stable machine-level signals (OS, architecture, hostname hash)
//! and produces a deterministic SHA-256 hex digest. The fingerprint is sent
//! to the server via the `X-Device-Fingerprint` header where it is folded
//! into the server-side device hash for stronger device identification.
//!
//! # Privacy
//!
//! The hostname is hashed — the raw value never leaves the process.

use sha2::{Digest, Sha256};

/// Compute a deterministic device fingerprint for the current machine.
///
/// Components used:
/// - OS name (`std::env::consts::OS`)
/// - Architecture (`std::env::consts::ARCH`)
/// - Hostname (SHA-256 hashed — never sent in plaintext)
///
/// The result is a 64-character hex string (SHA-256).
pub fn compute_fingerprint() -> String {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let hostname_hash = hash_hostname();

    let raw = format!("{}|{}|{}", os, arch, hostname_hash);
    hex::encode(Sha256::digest(raw.as_bytes()))
}

fn hash_hostname() -> String {
    let hostname = hostname();
    hex::encode(Sha256::digest(hostname.as_bytes()))
}

#[cfg(unix)]
fn hostname() -> String {
    // Read from /etc/hostname or fall back to "unknown"
    std::fs::read_to_string("/etc/hostname")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(windows)]
fn hostname() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(not(any(unix, windows)))]
fn hostname() -> String {
    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_64_hex_chars() {
        let fp = compute_fingerprint();
        assert_eq!(fp.len(), 64);
        assert!(fp.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn fingerprint_is_deterministic() {
        let a = compute_fingerprint();
        let b = compute_fingerprint();
        assert_eq!(a, b);
    }
}
