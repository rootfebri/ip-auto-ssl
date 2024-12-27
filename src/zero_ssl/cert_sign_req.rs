use crate::args::Args;
use clap::Parser;
use rcgen::{generate_simple_self_signed, CertificateSigningRequest, CertifiedKey, KeyPair};

pub(crate) struct CertSignReq {
    pub(crate) certificate_signing_request: CertificateSigningRequest,
    pub(crate) key_pair: KeyPair,
}

impl Default for CertSignReq {
    fn default() -> Self {
        let alt_names = vec![Args::parse().domain];
        let CertifiedKey { key_pair, cert } = generate_simple_self_signed(alt_names)
            .expect("Failed to generate simple Self Signed Certificate");
        let certificate_signing_request = cert
            .params()
            .serialize_request(&key_pair)
            .expect("Failed to get CSR");

        Self {
            key_pair,
            certificate_signing_request,
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test() -> std::io::Result<()> {
        let csr = CertSignReq::default();
        dbg!(&csr.certificate_signing_request.pem().unwrap());
        dbg!(&csr.key_pair.serialize_pem());
        Ok(())
    }
}
