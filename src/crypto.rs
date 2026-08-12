//! Identities, fingerprints and the two custom certificate verifiers.
//!
//! qsh deliberately does not use a public PKI. Both ends hold a long-lived
//! self-signed Ed25519 certificate:
//!
//! * the client pins the server's public key (`known_hosts`),
//! * the server authorises individual client public keys and maps them to a
//!   local Unix user (`authorized/`).
//!
//! Both directions additionally enforce the certificate's validity window, so
//! an expired certificate stops working on its own.

use std::fmt::Debug;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::Path;
use std::sync::Arc;

use anyhow::{anyhow, bail, Context, Result};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{DigitallySignedStruct, DistinguishedName, Error as TlsError, SignatureScheme};
use sha2::{Digest, Sha256};
use x509_parser::prelude::*;

/// A public key fingerprint: SHA-256 over the certificate's
/// `SubjectPublicKeyInfo`. Stable across certificate renewals of the same key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// Compute the fingerprint of a DER-encoded certificate.
    ///
    /// # Errors
    /// Fails if the bytes are not a parseable X.509 certificate.
    pub fn of_cert(der: &[u8]) -> Result<Self> {
        let (_, cert) =
            X509Certificate::from_der(der).map_err(|e| anyhow!("malformed certificate: {e}"))?;
        Ok(Self(Sha256::digest(cert.public_key().raw).into()))
    }

    /// Parse the `sha256:<hex>` textual form.
    ///
    /// # Errors
    /// Fails if the prefix is missing or the digest is not 64 hex characters.
    pub fn parse(s: &str) -> Result<Self> {
        let hex = s
            .strip_prefix("sha256:")
            .ok_or_else(|| anyhow!("fingerprint must start with `sha256:`"))?
            .as_bytes();
        // Work on bytes, not chars: `hex.len() == 64` counts bytes, so slicing
        // the `str` at byte offsets could land inside a multi-byte character
        // and panic before the digits are ever validated.
        if hex.len() != 64 {
            bail!("fingerprint must be 64 hex characters");
        }
        let digit = |b: u8| -> Result<u8> {
            match b {
                b'0'..=b'9' => Ok(b - b'0'),
                b'a'..=b'f' => Ok(b - b'a' + 10),
                b'A'..=b'F' => Ok(b - b'A' + 10),
                _ => bail!("fingerprint contains non-hex characters"),
            }
        };
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            let (Some(&hi), Some(&lo)) = (hex.get(i * 2), hex.get(i * 2 + 1)) else {
                bail!("fingerprint must be 64 hex characters");
            };
            *byte = digit(hi)? << 4 | digit(lo)?;
        }
        Ok(Self(out))
    }
}

impl std::fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "sha256:")?;
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

/// A certificate plus its private key, as held by a client or a server.
#[derive(Debug)]
pub struct Identity {
    pub cert: CertificateDer<'static>,
    pub key: PrivateKeyDer<'static>,
}

impl Identity {
    /// This identity's public key fingerprint.
    ///
    /// # Errors
    /// Fails if the stored certificate cannot be parsed.
    pub fn fingerprint(&self) -> Result<Fingerprint> {
        Fingerprint::of_cert(&self.cert)
    }
}

/// Generate a fresh self-signed Ed25519 identity valid for `days` days.
///
/// Returns `(certificate_pem, private_key_pem)`.
///
/// # Errors
/// Fails if key generation or self-signing fails.
pub fn generate_identity(
    common_name: &str,
    sans: &[String],
    days: u32,
) -> Result<(String, String)> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)
        .context("generating an Ed25519 key pair")?;

    let mut params =
        rcgen::CertificateParams::new(sans.to_vec()).context("building certificate parameters")?;
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    params.is_ca = rcgen::IsCa::NoCa;
    params.use_authority_key_identifier_extension = false;
    params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
    // The same identity is used for host authentication and for client
    // authentication, depending on which side generated it.
    params.extended_key_usages = vec![
        rcgen::ExtendedKeyUsagePurpose::ServerAuth,
        rcgen::ExtendedKeyUsagePurpose::ClientAuth,
    ];

    let now = std::time::SystemTime::now();
    // A little backdating absorbs modest clock skew between the two hosts.
    generate_within(
        params,
        &key,
        now - std::time::Duration::from_secs(3600),
        now + std::time::Duration::from_secs(u64::from(days) * 86_400),
    )
}

/// Self-sign `params` with an explicit validity window.
fn generate_within(
    mut params: rcgen::CertificateParams,
    key: &rcgen::KeyPair,
    not_before: std::time::SystemTime,
    not_after: std::time::SystemTime,
) -> Result<(String, String)> {
    params.not_before = system_time_to_offset(not_before);
    params.not_after = system_time_to_offset(not_after);
    let cert = params
        .self_signed(key)
        .context("self-signing the certificate")?;
    Ok((cert.pem(), key.serialize_pem()))
}

/// Build an identity whose validity window is entirely in the past or the
/// future, so the checks that reject it can be tested.
///
/// # Errors
/// Fails if key generation or self-signing fails.
#[cfg(test)]
pub(crate) fn generate_identity_outside_validity(expired: bool) -> Result<(String, String)> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let params = rcgen::CertificateParams::new(vec!["qsh-test".to_owned()])?;
    let now = std::time::SystemTime::now();
    let day = std::time::Duration::from_secs(86_400);
    if expired {
        generate_within(params, &key, now - day * 3, now - day)
    } else {
        generate_within(params, &key, now + day, now + day * 3)
    }
}

fn system_time_to_offset(t: std::time::SystemTime) -> ::time::OffsetDateTime {
    ::time::OffsetDateTime::from(t)
}

/// Parse the first certificate out of a PEM string.
///
/// # Errors
/// Fails if the PEM is malformed or holds no certificate.
pub fn cert_from_pem(pem: &str) -> Result<CertificateDer<'static>> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    let first = rustls_pemfile::certs(&mut reader)
        .next()
        .transpose()
        .context("parsing a PEM certificate")?;
    first.ok_or_else(|| anyhow!("no certificate found"))
}

/// Read a PEM certificate file and return the first certificate in it.
///
/// # Errors
/// Fails if the file cannot be read or holds no certificate.
pub fn load_cert(path: &Path) -> Result<CertificateDer<'static>> {
    let pem = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let mut reader = std::io::BufReader::new(&pem[..]);
    let certs: Vec<_> = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<_, _>>()
        .with_context(|| format!("parsing certificates in {}", path.display()))?;
    certs
        .into_iter()
        .next()
        .ok_or_else(|| anyhow!("{} contains no certificate", path.display()))
}

/// Read a PEM private key file, insisting on owner-only permissions.
///
/// # Errors
/// Fails if the file is group- or world-accessible, cannot be read, or holds
/// no private key.
pub fn load_key(path: &Path) -> Result<PrivateKeyDer<'static>> {
    let meta = fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
    let mode = meta.permissions().mode() & 0o777;
    if mode & 0o077 != 0 {
        bail!(
            "private key {} is group/world accessible (mode {:04o}); run `chmod 600 {}`",
            path.display(),
            mode,
            path.display()
        );
    }
    let pem = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let mut reader = std::io::BufReader::new(&pem[..]);
    rustls_pemfile::private_key(&mut reader)
        .with_context(|| format!("parsing private key in {}", path.display()))?
        .ok_or_else(|| anyhow!("{} contains no private key", path.display()))
}

/// Load a certificate/key pair from disk.
///
/// # Errors
/// Fails if either file is missing, unreadable, or badly permissioned.
pub fn load_identity(cert_path: &Path, key_path: &Path) -> Result<Identity> {
    Ok(Identity {
        cert: load_cert(cert_path)?,
        key: load_key(key_path)?,
    })
}

/// Write a file that only its owner may read.
///
/// # Errors
/// Fails if the parent directory or the file itself cannot be created.
pub fn write_private(path: &Path, contents: &str) -> Result<()> {
    write_atomically(path, contents, 0o600)
}

/// Write a world-readable file (certificates, configuration).
///
/// # Errors
/// Fails if the parent directory or the file itself cannot be created.
pub fn write_public(path: &Path, contents: &str) -> Result<()> {
    write_atomically(path, contents, 0o644)
}

/// Write `contents` to `path` without ever leaving it half-written.
///
/// Truncating the destination in place would let a crash or a short write
/// destroy the only copy of a host key, and would follow a symlink an attacker
/// planted. Instead a fresh temporary file is created in the same directory
/// (`create_new`, so it cannot be an existing symlink), given its final mode
/// before any data reaches it, flushed to disk, and then renamed over the
/// destination — an atomic replacement. The directory is fsynced afterwards so
/// the rename itself survives a power cut.
fn write_atomically(path: &Path, contents: &str, mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;

    let file_name = path
        .file_name()
        .ok_or_else(|| anyhow!("{} is not a file path", path.display()))?;
    let tmp = parent.join(format!(
        ".{}.tmp.{}",
        file_name.to_string_lossy(),
        std::process::id()
    ));
    // A leftover temporary from a previous crash must not block the write.
    let _ = fs::remove_file(&tmp);

    let write = || -> Result<()> {
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)
            .with_context(|| format!("creating {}", tmp.display()))?;
        f.write_all(contents.as_bytes())
            .with_context(|| format!("writing {}", tmp.display()))?;
        f.sync_all()
            .with_context(|| format!("flushing {}", tmp.display()))?;
        Ok(())
    };
    if let Err(e) = write() {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }

    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(e).with_context(|| format!("replacing {}", path.display()));
    }
    // Persist the rename itself; failure here is not worth aborting over.
    if let Ok(dir) = fs::File::open(parent) {
        let _ = dir.sync_all();
    }
    Ok(())
}

/// Reject certificates that are not currently within their validity window.
///
/// # Errors
/// Fails if the certificate cannot be parsed, has expired, or is not yet valid.
pub fn check_validity(der: &[u8], now: UnixTime) -> std::result::Result<(), TlsError> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|_| TlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
    let seconds = i64::try_from(now.as_secs())
        .map_err(|_| TlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
    let now = ASN1Time::from_timestamp(seconds)
        .map_err(|_| TlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
    if now < cert.validity().not_before {
        return Err(TlsError::InvalidCertificate(
            rustls::CertificateError::NotValidYet,
        ));
    }
    if now > cert.validity().not_after {
        return Err(TlsError::InvalidCertificate(
            rustls::CertificateError::Expired,
        ));
    }
    Ok(())
}

fn supported_schemes() -> Vec<SignatureScheme> {
    rustls::crypto::ring::default_provider()
        .signature_verification_algorithms
        .supported_schemes()
}

fn verify_signature(
    message: &[u8],
    cert: &CertificateDer<'_>,
    dss: &DigitallySignedStruct,
) -> std::result::Result<HandshakeSignatureValid, TlsError> {
    rustls::crypto::verify_tls13_signature(
        message,
        cert,
        dss,
        &rustls::crypto::ring::default_provider().signature_verification_algorithms,
    )
}

/// Client-side verifier: the server's public key must equal the pinned one.
#[derive(Debug)]
pub struct PinnedServerVerifier {
    expected: Fingerprint,
}

impl PinnedServerVerifier {
    #[must_use]
    pub fn new(expected: Fingerprint) -> Arc<Self> {
        Arc::new(Self { expected })
    }
}

impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, TlsError> {
        check_validity(end_entity, now)?;
        let got = Fingerprint::of_cert(end_entity)
            .map_err(|_| TlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
        if got != self.expected {
            return Err(TlsError::InvalidCertificate(
                rustls::CertificateError::Other(rustls::OtherError(Arc::new(HostKeyMismatch {
                    got,
                    expected: self.expected,
                }))),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        // QUIC mandates TLS 1.3.
        Err(TlsError::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        verify_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        supported_schemes()
    }
}

/// Error surfaced when the presented host key differs from the pinned one.
#[derive(Debug)]
pub struct HostKeyMismatch {
    pub got: Fingerprint,
    pub expected: Fingerprint,
}

impl std::fmt::Display for HostKeyMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "host key mismatch: expected {}, got {}",
            self.expected, self.got
        )
    }
}

impl std::error::Error for HostKeyMismatch {}

/// Server-side verifier: the client must present a certificate whose public
/// key is listed as authorised. The mapping to a local user is resolved
/// afterwards, from the certificate the handshake exposes.
///
/// The predicate is consulted per handshake rather than baked in at start-up,
/// so revoking a client takes effect on the next connection without a restart.
pub struct AuthorizedClientVerifier {
    is_allowed: Arc<dyn Fn(&Fingerprint) -> bool + Send + Sync>,
}

impl Debug for AuthorizedClientVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("AuthorizedClientVerifier")
    }
}

impl AuthorizedClientVerifier {
    pub fn new(is_allowed: Arc<dyn Fn(&Fingerprint) -> bool + Send + Sync>) -> Arc<Self> {
        Arc::new(Self { is_allowed })
    }
}

impl ClientCertVerifier for AuthorizedClientVerifier {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    fn offer_client_auth(&self) -> bool {
        true
    }

    fn client_auth_mandatory(&self) -> bool {
        true
    }

    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> std::result::Result<ClientCertVerified, TlsError> {
        check_validity(end_entity, now)?;
        let got = Fingerprint::of_cert(end_entity)
            .map_err(|_| TlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
        if !(self.is_allowed)(&got) {
            return Err(TlsError::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ));
        }
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        Err(TlsError::PeerIncompatible(
            rustls::PeerIncompatible::Tls12NotOffered,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, TlsError> {
        verify_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        supported_schemes()
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing,
    reason = "a failing assertion should panic loudly; that is the point of a test"
)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable_and_round_trips() {
        let (cert_pem, _) = generate_identity("test", &["localhost".into()], 30).unwrap();
        let der = cert_from_pem(&cert_pem).unwrap();

        let fp = Fingerprint::of_cert(&der).unwrap();
        assert_eq!(Fingerprint::of_cert(&der).unwrap(), fp);
        assert_eq!(Fingerprint::parse(&fp.to_string()).unwrap(), fp);
        assert!(fp.to_string().starts_with("sha256:"));
    }

    #[test]
    fn distinct_identities_have_distinct_fingerprints() {
        let (a, _) = generate_identity("a", &["a".into()], 30).unwrap();
        let (b, _) = generate_identity("b", &["b".into()], 30).unwrap();
        assert_ne!(
            Fingerprint::of_cert(&cert_from_pem(&a).unwrap()).unwrap(),
            Fingerprint::of_cert(&cert_from_pem(&b).unwrap()).unwrap()
        );
    }

    #[test]
    fn bad_fingerprints_are_rejected() {
        assert!(Fingerprint::parse("deadbeef").is_err());
        assert!(Fingerprint::parse("sha256:xyz").is_err());
        assert!(Fingerprint::parse(&format!("sha256:{}", "z".repeat(64))).is_err());
    }

    #[test]
    fn expired_certificates_are_rejected() {
        let (pem, _) = generate_identity("old", &["localhost".into()], 1).unwrap();
        let der = cert_from_pem(&pem).unwrap();

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(check_validity(
            &der,
            UnixTime::since_unix_epoch(std::time::Duration::from_secs(now))
        )
        .is_ok());
        // Two days later the one-day certificate is dead.
        let later = UnixTime::since_unix_epoch(std::time::Duration::from_secs(now + 2 * 86_400));
        assert!(check_validity(&der, later).is_err());
    }

    #[test]
    fn private_keys_are_written_owner_only() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id.key");
        write_private(&path, "secret").unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        assert!(
            load_key(&path).is_err(),
            "not a real key, must fail to parse"
        );
    }

    #[test]
    fn group_readable_keys_are_refused() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id.key");
        let (_, key_pem) = generate_identity("x", &["localhost".into()], 30).unwrap();
        write_private(&path, &key_pem).unwrap();
        assert!(load_key(&path).is_ok());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let err = load_key(&path).unwrap_err().to_string();
        assert!(err.contains("group/world accessible"), "{err}");
    }
}
