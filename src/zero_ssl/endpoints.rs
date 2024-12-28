use crate::zero_ssl::json::ZeroSSLCreateCertificate;
use crate::{cv_err, Args, API};
use clap::Parser;
use reqwest::Client;
use serde::de::DeserializeOwned;
use serde_json::Value;
use std::io;

pub(crate) enum ZeroSslApi<'a> {
    CreateCertificate(&'a Value),
    VerifyDomains(&'a ZeroSSLCreateCertificate),
    _VerificationStatus(&'a ZeroSSLCreateCertificate),
    DownloadCertificate(&'a ZeroSSLCreateCertificate),
}

impl ZeroSslApi<'_> {
    pub(crate) async fn request<T>(&self) -> io::Result<T>
    where
        T: DeserializeOwned,
    {
        use ZeroSslApi::*;

        let Args { access_key, .. } = Args::parse();
        match *self {
            CreateCertificate(post_data) => {
                let url = format!("{API}/certificates?access_key={access_key}");
                let response = Client::new()
                    .post(url)
                    .json(post_data)
                    .send()
                    .await
                    .map_err(cv_err)?;
                let json_text = response.text().await.map_err(cv_err)?;
                let json = serde_json::from_str::<T>(&json_text).map_err(cv_err);
                if let Err(ref msg) = json {
                    println!(
                        "Error when converting text response to ZSL: {}, original value: \n{:#}",
                        msg, json_text
                    );
                }
                json
            }
            VerifyDomains(zsl) => {
                let url = format!(
                    "{API}/certificates/{}/challenges?access_key={access_key}&validation_method=HTTP_CSR_HASH", zsl.id
                );

                let json_text = Client::new()
                    .post(url)
                    .send()
                    .await
                    .map_err(cv_err)?
                    .text()
                    .await
                    .map_err(cv_err)?;

                match serde_json::from_str(&json_text) {
                    Ok(val) => Ok(val),
                    Err(error) => {
                        println!("{}", json_text);
                        Err(cv_err(error))
                    }
                }
            }
            _VerificationStatus(zsl) => {
                let url = format!(
                    "{API}/certificates/{}/status?access_key={access_key}",
                    zsl.id
                );

                Client::new()
                    .post(url)
                    .send()
                    .await
                    .map_err(cv_err)?
                    .json()
                    .await
                    .map_err(cv_err)
            }
            DownloadCertificate(zsl) => {
                let url = format!("{API}/certificates/{}/download/return", zsl.id);
                let json_text = Client::new()
                    .get(url)
                    .send()
                    .await
                    .map_err(cv_err)?
                    .text()
                    .await
                    .map_err(cv_err)?;

                match serde_json::from_str(&json_text) {
                    Ok(val) => Ok(val),
                    Err(error) => {
                        println!("{}", json_text);
                        Err(cv_err(error))
                    }
                }
            }
        }
    }
}
