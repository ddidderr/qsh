//! Host spelling shared by connection setup and the known-hosts database.

use std::net::{IpAddr, Ipv6Addr, SocketAddr, ToSocketAddrs};

use anyhow::{bail, Context, Result};
use rustls::pki_types::DnsName;

/// A validated host name or address, without a port or IPv6 brackets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct HostName {
    name: String,
    identity: String,
    is_address: bool,
    is_ipv6: bool,
}

impl HostName {
    /// Normalize only spellings that have the same resolver meaning.
    ///
    /// Absolute DNS names retain their final dot: removing it can enable the
    /// resolver's search suffixes. Resolvable IPv6 interface names use the
    /// numeric scope ID returned by the same platform resolver used to connect.
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
            let name = ip.to_string();
            return Ok(Self {
                identity: name.clone(),
                name,
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
            let (scope, identity_scope) = if scope.bytes().all(|b| b.is_ascii_digit()) {
                let scope = scope.parse::<u32>().context("IPv6 scope is too large")?;
                let scope = (scope != 0).then(|| scope.to_string());
                (scope.clone(), scope)
            } else {
                let identity = match resolve_named_scope(address, scope) {
                    ScopeResolution::Unresolved => Some(scope.to_owned()),
                    ScopeResolution::Default => None,
                    ScopeResolution::Index(scope) => Some(scope.to_string()),
                };
                (Some(scope.to_owned()), identity)
            };
            return Ok(Self {
                name: scoped_address(address, scope.as_deref()),
                identity: scoped_address(address, identity_scope.as_deref()),
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
        let name = host.to_ascii_lowercase();
        Ok(Self {
            identity: name.clone(),
            name,
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

    #[must_use]
    fn identity_key(&self, port: u16) -> String {
        if self.is_ipv6 {
            format!("[{}]:{port}", self.identity)
        } else {
            format!("{}:{port}", self.identity)
        }
    }
}

fn scoped_address(address: Ipv6Addr, scope: Option<&str>) -> String {
    scope.map_or_else(|| address.to_string(), |scope| format!("{address}%{scope}"))
}

/// Resolve an interface name through the same platform path connection setup
/// uses. This preserves platform acceptance rules while merging names and
/// numeric indices that produce the same effective IPv6 socket scope.
enum ScopeResolution {
    Unresolved,
    Default,
    Index(u32),
}

fn resolve_named_scope(address: Ipv6Addr, scope: &str) -> ScopeResolution {
    let scoped = format!("{address}%{scope}");
    let Some(scope) = (scoped.as_str(), 0)
        .to_socket_addrs()
        .ok()
        .and_then(|mut sockets| {
            sockets.find_map(|socket| match socket {
                SocketAddr::V6(socket) if *socket.ip() == address => Some(socket.scope_id()),
                _ => None,
            })
        })
    else {
        return ScopeResolution::Unresolved;
    };
    if scope == 0 {
        ScopeResolution::Default
    } else {
        ScopeResolution::Index(scope)
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

pub(super) fn canonical_identity_key(input: &str) -> Result<String> {
    let (host, port) = input
        .rsplit_once(':')
        .context("known host must include a port: host:port or [IPv6]:port")?;
    if port.is_empty() || !port.bytes().all(|b| b.is_ascii_digit()) {
        bail!("invalid known-host port");
    }
    let port = port
        .parse::<u16>()
        .context("known-host port is too large")?;
    Ok(HostName::parse(host)?.identity_key(port))
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
            ("[::1%0]:2222", "[::1]:2222"),
            ("::1%000:2222", "[::1]:2222"),
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
        assert_ne!(
            canonical_key("fe80::1%1:1").unwrap(),
            canonical_key("fe80::1%2:1").unwrap()
        );
    }

    #[test]
    fn resolver_equivalent_scopes_share_identity_but_preserve_the_name() {
        for interface in ["lo", "lo0"] {
            let named = format!("fe80::1%{interface}");
            let Ok(mut resolved) = (named.as_str(), 0).to_socket_addrs() else {
                continue;
            };
            let Some(SocketAddr::V6(socket)) = resolved.find(SocketAddr::is_ipv6) else {
                continue;
            };
            if socket.scope_id() == 0 {
                continue;
            }
            let named_host = HostName::parse(&named).unwrap();
            assert_eq!(
                named_host.identity_key(2222),
                HostName::parse(&format!("fe80::1%{}", socket.scope_id()))
                    .unwrap()
                    .identity_key(2222)
            );
            assert_eq!(named_host.key(2222), format!("[{named}]:2222"));
            return;
        }
        eprintln!("skipping named IPv6 scope test: no loopback interface name resolved");
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
