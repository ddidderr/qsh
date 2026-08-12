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
/// SubjectPublicKeyInfo. Stable across certificate renewals of the same key.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    /// Compute the fingerprint of a DER-encoded certificate.
    pub fn of_cert(der: &[u8]) -> Result<Self> {
        let (_, cert) =
            X509Certificate::from_der(der).map_err(|e| anyhow!("malformed certificate: {e}"))?;
        Ok(Self(Sha256::digest(cert.public_key().raw).into()))
    }

    /// Parse the `sha256:<hex>` textual form.
    pub fn parse(s: &str) -> Result<Self> {
        let hex = s
            .strip_prefix("sha256:")
            .ok_or_else(|| anyhow!("fingerprint must start with `sha256:`"))?;
        if hex.len() != 64 {
            bail!("fingerprint must be 64 hex characters");
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
                .map_err(|_| anyhow!("fingerprint contains non-hex characters"))?;
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
    pub fn fingerprint(&self) -> Result<Fingerprint> {
        Fingerprint::of_cert(&self.cert)
    }
}

/// Generate a fresh self-signed Ed25519 identity valid for `days` days.
///
/// Returns `(certificate_pem, private_key_pem)`.
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
    params.not_before = system_time_to_offset(now - std::time::Duration::from_secs(3600))?;
    params.not_after =
        system_time_to_offset(now + std::time::Duration::from_secs(u64::from(days) * 86_400))?;

    let cert = params
        .self_signed(&key)
        .context("self-signing the certificate")?;
    Ok((cert.pem(), key.serialize_pem()))
}

fn system_time_to_offset(t: std::time::SystemTime) -> Result<::time::OffsetDateTime> {
    Ok(::time::OffsetDateTime::from(t))
}

/// Parse the first certificate out of a PEM string.
pub fn cert_from_pem(pem: &str) -> Result<CertificateDer<'static>> {
    let mut reader = std::io::BufReader::new(pem.as_bytes());
    let first = rustls_pemfile::certs(&mut reader)
        .next()
        .transpose()
        .context("parsing a PEM certificate")?;
    first.ok_or_else(|| anyhow!("no certificate found"))
}

/// Read a PEM certificate file and return the first certificate in it.
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
pub fn load_identity(cert_path: &Path, key_path: &Path) -> Result<Identity> {
    Ok(Identity {
        cert: load_cert(cert_path)?,
        key: load_key(key_path)?,
    })
}

/// Write a file that only its owner may read.
pub fn write_private(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("creating {}", path.display()))?;
    f.write_all(contents.as_bytes())
        .with_context(|| format!("writing {}", path.display()))?;
    // create(true) does not change the mode of a pre-existing file.
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// Write a world-readable file (certificates, configuration).
pub fn write_public(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).with_context(|| format!("creating {}", parent.display()))?;
    }
    fs::write(path, contents).with_context(|| format!("writing {}", path.display()))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o644))?;
    Ok(())
}

/// Reject certificates that are not currently within their validity window.
fn check_validity(der: &[u8], now: UnixTime) -> std::result::Result<(), TlsError> {
    let (_, cert) = X509Certificate::from_der(der)
        .map_err(|_| TlsError::InvalidCertificate(rustls::CertificateError::BadEncoding))?;
    let now = ASN1Time::from_timestamp(now.as_secs() as i64)
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
