use crate::cv_err;
use crate::zero_ssl::endpoints::ZeroSslApi;
use crate::zero_ssl::json::{
    CertificatesFile, DomainVerificationResponse, ZeroSSLCreateCertificate,
};
use crate::zero_ssl::CertSignReq;
use serde_json::json;
use std::io;
use std::time::Duration;

pub(crate) struct CreateZeroSSLCertificate {
    domain: String,
}

impl CreateZeroSSLCertificate {
    pub(crate) fn domain(&self) -> &String {
        &self.domain
    }

    pub(crate) async fn certificate(
        &self,
        zero_ssl_response: &ZeroSSLCreateCertificate,
    ) -> io::Result<CertificatesFile> {
        ZeroSslApi::DownloadCertificate(zero_ssl_response)
            .request()
            .await
            .map_err(cv_err)
    }
    async fn check(
        &self,
        zero_ssl_response: &ZeroSSLCreateCertificate,
    ) -> io::Result<DomainVerificationResponse> {
        ZeroSslApi::VerifyDomains(zero_ssl_response)
            .request()
            .await
            .map_err(cv_err)
    }

    pub(crate) async fn verify(
        &self,
        zero_ssl_response: &ZeroSSLCreateCertificate,
    ) -> io::Result<()> {
        loop {
            match self.check(zero_ssl_response).await {
                Ok(status) => {
                    if status.success {
                        println!("Verifying {}... Success", zero_ssl_response.common_name);
                        break;
                    } else {
                        println!("Verifying {}...", zero_ssl_response.common_name);
                        tokio::time::sleep(Duration::from_secs(3)).await;
                    }
                }
                Err(error) => {
                    panic!("{}", error)
                }
            }
        }

        Ok(())
    }

    pub(crate) fn new<D: Into<String>>(domain: D) -> Self {
        Self {
            domain: domain.into(),
        }
    }

    pub(crate) async fn create(&self, csr: &CertSignReq) -> io::Result<ZeroSSLCreateCertificate> {
        let post_data = json!({"certificate_domains": &self.domain, "certificate_csr": csr.certificate_signing_request.pem().unwrap(), "certificate_validity_days": 90, "strict_domains": 1});

        ZeroSslApi::CreateCertificate(&post_data)
            .request()
            .await
            .map_err(cv_err)
    }
}
