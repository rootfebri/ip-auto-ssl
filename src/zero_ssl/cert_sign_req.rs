use crate::args::Args;
use clap::Parser;
use rcgen::{CertificateParams, CertificateSigningRequest, DnType, KeyPair};

pub(crate) struct CertSignReq {
    pub(crate) certificate_params: CertificateParams,
    pub(crate) certificate_signing_request: CertificateSigningRequest,
    pub(crate) key_pair: KeyPair,
}

impl CertSignReq {
    fn new() -> Self {
        let key_pair = KeyPair::generate().unwrap();
        let certificate_params = CertificateParams::default();

        let certificate_signing_request = certificate_params
            .serialize_request(&key_pair)
            .expect("Failed to create CertificateSigningRequest");

        Self {
            certificate_params,
            certificate_signing_request,
            key_pair,
        }
        .setup_dn()
    }

    fn setup_dn(mut self) -> Self {
        self.certificate_params
            .distinguished_name
            .push(DnType::CommonName, Args::parse().domain);
        self.certificate_params
            .distinguished_name
            .push(DnType::CountryName, "US");
        self.certificate_params
            .distinguished_name
            .push(DnType::OrganizationName, "BenihTOTO");
        self.certificate_signing_request = self
            .certificate_params
            .serialize_request(&self.key_pair)
            .expect("Failed to update CertificateSigningRequest");
        self
    }
}

impl Default for CertSignReq {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::env::set_var;

    #[test]
    fn generate_csr_and_key_pair() -> std::io::Result<()> {
        set_var("ZEROSSL_ACCESS_KEY", "94f6aee24ad14d358bcce229c3382d56");
        let csr = CertSignReq::default();
        dbg!(&csr.certificate_signing_request.pem().unwrap());
        dbg!(&csr.key_pair.serialize_pem());
        Ok(())
    }
}
