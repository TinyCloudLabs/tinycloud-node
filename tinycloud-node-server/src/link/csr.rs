//! TLS keypair + CSR generation for `<name>.local.tinycloud.link`.
//!
//! The service enforces (`assertCsrMatchesDomain` in `names.ts`) that the CN
//! and the entire SAN set is exactly the expected domain as a single dNSName
//! entry. We emit exactly that shape here so the service never rejects the CSR.
use rcgen::{
    CertificateParams, DistinguishedName, DnType, KeyPair, SanType, PKCS_ECDSA_P256_SHA256,
};

use super::LinkError;

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

/// Generate a fresh ECDSA P-256 keypair + a PKCS#10 CSR whose CN and single
/// SAN dNSName entry are both `<name>.local.tinycloud.link`. This matches
/// `assertCsrMatchesDomain(csrPem, expectedDomain)` in the link service.
pub fn generate_csr(name: &str) -> Result<CsrBundle, LinkError> {
    let domain = fqdn_for_name(name);

    let keypair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256)
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
}
