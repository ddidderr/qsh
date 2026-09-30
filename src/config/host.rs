//! Host spelling shared by connection setup and the known-hosts database.

use std::net::{IpAddr, Ipv6Addr};

use anyhow::{bail, Context, Result};
use rustls::pki_types::DnsName;

/// A validated host name or address, without a port or IPv6 brackets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostName {
    name: String,
    is_address: bool,
    is_ipv6: bool,
}

impl HostName {
    /// Normalize only spellings that have the same resolver meaning.
    ///
    /// Absolute DNS names retain their final dot: removing it can enable the
    /// resolver's search suffixes. IPv6 interface names retain their case.
    ///
    /// # Errors
    /// Fails for malformed DNS names, IP addresses or IPv6 scope identifiers.
    pub(crate) fn parse(input: &str) -> Result<Self> {
        let bracketed = input.starts_with('[');
        let host = if bracketed {
            input
                .strip_prefix('[')
                .and_then(|host| host.strip_suffix(']'))
                .context("IPv6 address is missing its closing bracket")?
        } else {
            input
        };
        if let Ok(ip) = host.parse::<IpAddr>() {
            if bracketed && !ip.is_ipv6() {
                bail!("brackets are only valid around an IPv6 address");
            }
            return Ok(Self {
                name: ip.to_string(),
                is_address: true,
                is_ipv6: ip.is_ipv6(),
            });
        }
        if let Some((address, scope)) = host.split_once('%') {
            let address: Ipv6Addr = address.parse().context("invalid scoped IPv6 address")?;
            if scope.is_empty()
                || !scope
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
            {
                bail!("invalid IPv6 scope identifier");
            }
            let scope = if scope.bytes().all(|b| b.is_ascii_digit()) {
                scope
                    .parse::<u32>()
                    .context("IPv6 scope is too large")?
                    .to_string()
            } else {
                scope.to_owned()
            };
            return Ok(Self {
                name: format!("{address}%{scope}"),
                is_address: true,
                is_ipv6: true,
            });
        }
        if bracketed {
            bail!("brackets are only valid around an IPv6 address");
        }
        // Some libc resolvers accept abbreviated, octal or hex IPv4 forms.
        // Reject these instead of treating an address as an independent DNS pin.
        if host.split('.').all(|part| {
            !part.is_empty()
                && (part.bytes().all(|b| b.is_ascii_digit())
                    || part
                        .strip_prefix("0x")
                        .or_else(|| part.strip_prefix("0X"))
                        .is_some_and(|hex| {
                            !hex.is_empty() && hex.bytes().all(|b| b.is_ascii_hexdigit())
                        }))
        }) {
            bail!("use a canonical IPv4 address");
        }
        DnsName::try_from(host).context("invalid host name")?;
        Ok(Self {
            name: host.to_ascii_lowercase(),
            is_address: false,
            is_ipv6: false,
        })
    }

    #[must_use]
    pub(crate) fn as_str(&self) -> &str {
        &self.name
    }

    /// IP literals use a fixed SNI name because authentication pins the key.
    #[must_use]
    pub(crate) fn server_name(&self) -> &str {
        if self.is_address {
            "qsh"
        } else {
            &self.name
        }
    }

    #[must_use]
    pub(crate) fn key(&self, port: u16) -> String {
        if self.is_ipv6 {
            format!("[{}]:{port}", self.name)
        } else {
            format!("{}:{port}", self.name)
        }
    }
}

/// Also accept the unbracketed IPv6 entries written by older qsh clients.
pub(super) fn canonical_key(input: &str) -> Result<String> {
    let (host, port) = input
        .rsplit_once(':')
        .context("known host must include a port: host:port or [IPv6]:port")?;
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        bail!("invalid known-host port");
    }
    let port = port
        .parse::<u16>()
        .context("known-host port is too large")?;
    Ok(HostName::parse(host)?.key(port))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, reason = "tests assert successful parsing")]
mod tests {
    use super::*;

    #[test]
    fn equivalent_spellings_share_a_key() {
        for (input, expected) in [
            ("EXAMPLE.com:02222", "example.com:2222"),
            ("EXAMPLE.com.:2222", "example.com.:2222"),
            ("[2001:0DB8:0:0:0:0:0:1]:2222", "[2001:db8::1]:2222"),
            ("2001:DB8::1:2222", "[2001:db8::1]:2222"),
            ("[FE80::1%NetA]:2222", "[fe80::1%NetA]:2222"),
            ("fe80::1%002:2222", "[fe80::1%2]:2222"),
        ] {
            assert_eq!(canonical_key(input).unwrap(), expected);
        }
        assert_ne!(
            canonical_key("h:1").unwrap(),
            canonical_key("h.:1").unwrap()
        );
        assert_ne!(
            canonical_key("fe80::1%NetA:1").unwrap(),
            canonical_key("fe80::1%neta:1").unwrap()
        );
    }

    #[test]
    fn malformed_or_ambiguous_hosts_are_rejected_before_lookup() {
        for host in [
            "",
            "example.com..",
            "bad name",
            "a/b",
            "user@host",
            "[example.com]",
            "[[::1]]",
            "[::1",
            "::1]",
            "127.1",
            "0x7f000001",
            "127.0.0.01",
            "[fe80::1%]",
            "fe80::1%bad scope",
            "fe80::1%one%two",
        ] {
            assert!(HostName::parse(host).is_err(), "{host}");
        }
        for key in ["host", "host:", "host:+22", "host:65536", "host:abc"] {
            assert!(canonical_key(key).is_err(), "{key}");
        }
    }

    #[test]
    fn sni_and_resolution_use_the_same_validated_host() {
        for host in ["192.0.2.1", "[::1]", "fe80::1%NetA"] {
            assert_eq!(HostName::parse(host).unwrap().server_name(), "qsh");
        }
        let host = HostName::parse("Example.COM.").unwrap();
        assert_eq!(host.as_str(), "example.com.");
        assert_eq!(host.server_name(), "example.com.");
    }
}
