//! IP-based access control.
//!
//! This module implements IP allowlisting and blocklisting using CIDR notation
//! for network-based access control.

use crate::config_types::IpAccessConfig;
use ipnetwork::IpNetwork;
use std::net::IpAddr;

/// IP access filter supporting allowlists and blocklists.
#[derive(Debug, Clone)]
pub struct IpFilter {
    /// Allowed IP networks (if not empty, only these IPs are allowed).
    allowlist: Vec<IpNetwork>,
    /// Blocked IP networks (always checked, takes precedence over allowlist).
    blocklist: Vec<IpNetwork>,
}

impl IpFilter {
    /// Create a new IP filter from configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if any IP network string is invalid.
    pub fn new(config: &IpAccessConfig) -> Result<Self, anyhow::Error> {
        let allowlist = config.parse_allowlist()?;
        let blocklist = config.parse_blocklist()?;

        Ok(Self {
            allowlist,
            blocklist,
        })
    }

    /// Check if an IP address is allowed.
    ///
    /// # Logic
    ///
    /// 1. If IP is in blocklist, deny (even if in allowlist)
    /// 2. If allowlist is empty, allow (no restrictions)
    /// 3. If IP is in allowlist, allow
    /// 4. Otherwise, deny
    pub fn is_allowed(&self, ip: IpAddr) -> bool {
        // Check blocklist first (highest priority)
        if self.is_blocked(ip) {
            return false;
        }

        // If no allowlist configured, allow all (except blocked)
        if self.allowlist.is_empty() {
            return true;
        }

        // Check if IP is in allowlist
        self.is_in_allowlist(ip)
    }

    /// Check if an IP is in the blocklist.
    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        self.blocklist.iter().any(|network| network.contains(ip))
    }

    /// Check if an IP is in the allowlist.
    pub fn is_in_allowlist(&self, ip: IpAddr) -> bool {
        self.allowlist.iter().any(|network| network.contains(ip))
    }

    /// Get denial reason for an IP (for logging).
    pub fn denial_reason(&self, ip: IpAddr) -> Option<String> {
        if self.is_blocked(ip) {
            Some(format!("IP {} is in blocklist", ip))
        } else if !self.allowlist.is_empty() && !self.is_in_allowlist(ip) {
            Some(format!("IP {} is not in allowlist", ip))
        } else {
            None
        }
    }

    /// Check if filter has any restrictions (either allowlist or blocklist).
    pub fn has_restrictions(&self) -> bool {
        !self.allowlist.is_empty() || !self.blocklist.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    #[test]
    fn test_no_restrictions() {
        let config = IpAccessConfig {
            allowlist: vec![],
            blocklist: vec![],
        };
        let filter = IpFilter::new(&config).unwrap();

        // All IPs should be allowed when no restrictions
        assert!(filter.is_allowed(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert!(filter.is_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1))));
        assert!(!filter.has_restrictions());
    }

    #[test]
    fn test_allowlist_only() {
        let config = IpAccessConfig {
            allowlist: vec!["192.168.1.0/24".to_string(), "10.0.0.0/8".to_string()],
            blocklist: vec![],
        };
        let filter = IpFilter::new(&config).unwrap();

        // IPs in allowlist should be allowed
        assert!(filter.is_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        assert!(filter.is_allowed(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));

        // IPs not in allowlist should be denied
        assert!(!filter.is_allowed(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert!(!filter.is_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))));

        assert!(filter.has_restrictions());
    }

    #[test]
    fn test_blocklist_only() {
        let config = IpAccessConfig {
            allowlist: vec![],
            blocklist: vec!["1.2.3.4/32".to_string(), "192.168.1.0/24".to_string()],
        };
        let filter = IpFilter::new(&config).unwrap();

        // Blocked IPs should be denied
        assert!(!filter.is_allowed(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
        assert!(!filter.is_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));

        // Non-blocked IPs should be allowed
        assert!(filter.is_allowed(IpAddr::V4(Ipv4Addr::new(5, 6, 7, 8))));
        assert!(filter.is_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 2, 1))));

        assert!(filter.has_restrictions());
    }

    #[test]
    fn test_blocklist_precedence() {
        let config = IpAccessConfig {
            allowlist: vec!["192.168.1.0/24".to_string()],
            blocklist: vec!["192.168.1.100/32".to_string()],
        };
        let filter = IpFilter::new(&config).unwrap();

        // IP in both lists should be blocked (blocklist takes precedence)
        assert!(!filter.is_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));

        // IP only in allowlist should be allowed
        assert!(filter.is_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50))));

        // IP in neither list should be denied (allowlist is non-empty)
        assert!(!filter.is_allowed(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn test_ipv6_support() {
        let config = IpAccessConfig {
            allowlist: vec!["2001:db8::/32".to_string()],
            blocklist: vec!["2001:db8::1/128".to_string()],
        };
        let filter = IpFilter::new(&config).unwrap();

        // IPv6 in allowlist but not blocklist
        assert!(filter.is_allowed(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 2))));

        // IPv6 in blocklist
        assert!(!filter.is_allowed(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))));

        // IPv6 not in allowlist
        assert!(!filter.is_allowed(IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb9, 0, 0, 0, 0, 0, 1))));
    }

    #[test]
    fn test_single_ip_notation() {
        let config = IpAccessConfig {
            allowlist: vec!["192.168.1.100/32".to_string()],
            blocklist: vec![],
        };
        let filter = IpFilter::new(&config).unwrap();

        // Exact IP should be allowed
        assert!(filter.is_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));

        // Other IPs should be denied
        assert!(!filter.is_allowed(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101))));
    }

    #[test]
    fn test_invalid_network() {
        let config = IpAccessConfig {
            allowlist: vec!["invalid".to_string()],
            blocklist: vec![],
        };
        assert!(IpFilter::new(&config).is_err());
    }

    #[test]
    fn test_denial_reason() {
        let config = IpAccessConfig {
            allowlist: vec!["192.168.1.0/24".to_string()],
            blocklist: vec!["1.2.3.4/32".to_string()],
        };
        let filter = IpFilter::new(&config).unwrap();

        // Blocked IP
        let reason = filter.denial_reason(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        assert!(reason.is_some());
        assert!(reason.unwrap().contains("blocklist"));

        // Not in allowlist
        let reason = filter.denial_reason(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(reason.is_some());
        assert!(reason.unwrap().contains("not in allowlist"));

        // Allowed IP
        let reason = filter.denial_reason(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100)));
        assert!(reason.is_none());
    }

    #[test]
    fn test_is_blocked() {
        let config = IpAccessConfig {
            allowlist: vec![],
            blocklist: vec!["192.168.1.0/24".to_string()],
        };
        let filter = IpFilter::new(&config).unwrap();

        assert!(filter.is_blocked(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        assert!(!filter.is_blocked(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }

    #[test]
    fn test_is_in_allowlist() {
        let config = IpAccessConfig {
            allowlist: vec!["192.168.1.0/24".to_string()],
            blocklist: vec![],
        };
        let filter = IpFilter::new(&config).unwrap();

        assert!(filter.is_in_allowlist(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100))));
        assert!(!filter.is_in_allowlist(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
    }
}
