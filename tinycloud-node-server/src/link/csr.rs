//! TLS keypair + CSR generation for `<name>.local.tinycloud.link`.
//!
//! The service enforces (`assertCsrMatchesDomain` in `names.ts`) that the CN
//! and the entire SAN set is exactly the expected domain as a single dNSName
//! entry. We emit exactly that shape here so the service never rejects the CSR.
//!
//! The key pair is RSA-2048, not ECDSA. The service parses submitted CSRs with
//! `node-forge` (`forge.pki.certificationRequestFromPem` in `names.ts`), whose
//! CSR/X.509 support only understands RSA `SubjectPublicKeyInfo`s — an
//! EC (`id-ecPublicKey`) CSR is rejected with "Cannot read public key. OID is
//! not RSA." before `assertCsrMatchesDomain` ever runs. `rcgen`'s `ring`
//! backend cannot itself generate RSA keys, so we generate the key with the
//! `rsa` crate and hand the PKCS#8 DER to `rcgen::KeyPair::from_der_and_sign_algo`.
use rand::rngs::OsRng;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, SanType, PKCS_RSA_SHA256};
use rsa::{pkcs8::EncodePrivateKey, RsaPrivateKey};
use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

use super::LinkError;

/// RSA key size for the CSR keypair. 2048 bits is the minimum size accepted
/// by common CAs and matches what the TS service's own test CSRs use.
const RSA_KEY_BITS: usize = 2048;

/// TLS keypair + CSR bundle for a link-managed name.
pub struct CsrBundle {
    /// PEM-encoded PKCS#8 private key.
    pub private_key_pem: String,
    /// PEM-encoded PKCS#10 certificate signing request.
    pub csr_pem: String,
}

/// Compute the FQDN for a link name: `<name>.local.tinycloud.link`.
pub fn fqdn_for_name(name: &str) -> String {
    format!("{name}.{}", super::DOMAIN_SUFFIX)
}

/// Generate a fresh RSA-2048 keypair + a PKCS#10 CSR whose CN and single
/// SAN dNSName entry are both `<name>.local.tinycloud.link`. This matches
/// `assertCsrMatchesDomain(csrPem, expectedDomain)` in the link service.
pub fn generate_csr(name: &str) -> Result<CsrBundle, LinkError> {
    let domain = fqdn_for_name(name);

    let rsa_key = RsaPrivateKey::new(&mut OsRng, RSA_KEY_BITS)
        .map_err(|err| LinkError::Csr(err.to_string()))?;
    let pkcs8_der = rsa_key
        .to_pkcs8_der()
        .map_err(|err| LinkError::Csr(err.to_string()))?;
    let private_key_der =
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(pkcs8_der.as_bytes().to_vec()));
    let keypair = KeyPair::from_der_and_sign_algo(&private_key_der, &PKCS_RSA_SHA256)
        .map_err(|err| LinkError::Csr(err.to_string()))?;

    let mut params = CertificateParams::new(vec![domain.clone()])
        .map_err(|err| LinkError::Csr(err.to_string()))?;
    // The service checks that CN and the SAN set are both exactly `<domain>`,
    // and the SAN set contains only a single dNSName. `CertificateParams::new`
    // populates subject_alt_names[dNSName]=[domain]; we add the CN below.
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, domain.clone());
    params.distinguished_name = dn;
    params.subject_alt_names =
        vec![SanType::DnsName(domain.clone().try_into().map_err(
            |err: rcgen::Error| LinkError::Csr(err.to_string()),
        )?)];

    let csr = params
        .serialize_request(&keypair)
        .map_err(|err| LinkError::Csr(err.to_string()))?;
    let csr_pem = csr.pem().map_err(|err| LinkError::Csr(err.to_string()))?;
    let private_key_pem = keypair.serialize_pem();

    Ok(CsrBundle {
        private_key_pem,
        csr_pem,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fqdn_uses_local_tinycloud_link_suffix() {
        assert_eq!(fqdn_for_name("office"), "office.local.tinycloud.link");
        assert_eq!(
            fqdn_for_name("living-room"),
            "living-room.local.tinycloud.link"
        );
    }

    #[test]
    fn generated_csr_carries_expected_domain_in_cn_and_single_san_dns() {
        use x509_parser::prelude::FromDer;
        let bundle = generate_csr("mynode").expect("CSR generated");
        assert!(bundle.csr_pem.contains("BEGIN CERTIFICATE REQUEST"));
        assert!(bundle.private_key_pem.contains("BEGIN PRIVATE KEY"));

        // Parse the CSR to assert the CN and SAN structure the service requires.
        let der = pem::parse(&bundle.csr_pem).expect("PEM decode");
        let (_, csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(der.contents())
                .expect("parse CSR");
        let info = &csr.certification_request_info;

        // CN check.
        let cn = info
            .subject
            .iter_common_name()
            .next()
            .and_then(|cn| cn.as_str().ok())
            .expect("CN present");
        assert_eq!(cn, "mynode.local.tinycloud.link");

        // Extension check: exactly one SAN, one dNSName, exactly the domain.
        // Look up the extensionRequest attribute (OID 1.2.840.113549.1.9.14)
        // and walk its ParsedCriAttribute::ExtensionRequest wrapper.
        let mut san_dns_entries: Vec<String> = Vec::new();
        let mut non_dns_san = false;
        for attr in info.attributes() {
            if let x509_parser::cri_attributes::ParsedCriAttribute::ExtensionRequest(req) =
                attr.parsed_attribute()
            {
                for extension in &req.extensions {
                    if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) =
                        extension.parsed_extension()
                    {
                        for gn in &san.general_names {
                            match gn {
                                x509_parser::extensions::GeneralName::DNSName(name) => {
                                    san_dns_entries.push((*name).to_string());
                                }
                                _ => non_dns_san = true,
                            }
                        }
                    }
                }
            }
        }
        assert!(!non_dns_san, "SAN must contain only dNSName entries");
        assert_eq!(
            san_dns_entries,
            vec!["mynode.local.tinycloud.link".to_string()]
        );
    }

    // Regression guard: the link service parses CSRs with node-forge, which
    // only understands RSA `SubjectPublicKeyInfo`s (`forge.pki.certificationRequestFromAsn1`
    // throws "Cannot read public key. OID is not RSA." for EC keys). If this
    // ever drifts back to an EC keypair, every `link enable`/`renew` cert
    // request will be rejected with a 400 from the live service.
    #[test]
    fn generated_csr_public_key_is_rsa() {
        use x509_parser::prelude::FromDer;
        const RSA_ENCRYPTION_OID: &str = "1.2.840.113549.1.1.1";

        let bundle = generate_csr("mynode").expect("CSR generated");
        let der = pem::parse(&bundle.csr_pem).expect("PEM decode");
        let (_, csr) =
            x509_parser::certification_request::X509CertificationRequest::from_der(der.contents())
                .expect("parse CSR");
        let algorithm_oid = csr
            .certification_request_info
            .subject_pki
            .algorithm
            .algorithm
            .to_id_string();
        assert_eq!(algorithm_oid, RSA_ENCRYPTION_OID);
    }
}
