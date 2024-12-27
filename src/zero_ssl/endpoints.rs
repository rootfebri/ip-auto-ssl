use crate::zero_ssl::json::ZeroSSLCreateCertificate;
use crate::{Args, API};
use clap::Parser;
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde_json::Value;

pub(crate) enum ZeroSslApi<'a> {
    CreateCertificate(&'a Value),
    VerifyDomains(&'a ZeroSSLCreateCertificate),
    _VerificationStatus(&'a ZeroSSLCreateCertificate),
    DownloadCertificate(&'a ZeroSSLCreateCertificate),
}

impl ZeroSslApi<'_> {
    pub(crate) async fn request<T>(&self) -> reqwest::Result<T>
    where
        T: DeserializeOwned,
    {
        use ZeroSslApi::*;

        let Args { access_key, .. } = Args::parse();
        match *self {
            CreateCertificate(post_data) => {
                let url = format!("{API}/certificates?access_key={access_key}");
                Client::new()
                    .post(url)
                    .json(post_data)
                    .send()
                    .await?
                    .json::<T>()
                    .await
            }
            VerifyDomains(zsl) => {
                let url = format!(
                    "{API}/certificates/{}/challenges?access_key={access_key}&validation_method=HTTP_CSR_HASH", zsl.id
                );
                Client::new().post(url).send().await?.json::<T>().await
            }
            _VerificationStatus(zsl) => {
                let url = format!(
                    "{API}/certificates/{}/status?access_key={access_key}",
                    zsl.id
                );

                Client::new().post(url).send().await?.json::<T>().await
            }
            DownloadCertificate(zsl) => {
                let url = format!("{API}/certificates/{}/download/return", zsl.id);
                Client::new().get(url).send().await?.json::<T>().await
            }
        }
    }
}
