use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt::{Display, Formatter};
use std::io::{ErrorKind, Write};
use std::path::{Path, PathBuf};
use std::{fs, io};

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct ZeroSSLCreateCertificate {
    pub(crate) id: String,
    pub(crate) r#type: String,
    pub(crate) common_name: String,
    pub(crate) additional_domains: String,
    pub(crate) created: String,
    pub(crate) expires: String,
    pub(crate) status: String,
    pub(crate) validation: Validation,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct Validation {
    pub(crate) other_methods: HashMap<String, OtherMethodDetails>,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
pub(crate) struct OtherMethodDetails {
    pub(crate) file_validation_url_http: String,
    pub(crate) file_validation_content: Vec<String>,
}

// let file_validation_url_http = &self
// .file_validation_url_http
// .replace("http://", "")
// .replace(&Args::parse().domain, "")
// .trim_start_matches("/")
// .to_string();

impl ZeroSSLCreateCertificate {
    pub(crate) fn validation_path_destination(
        &self,
        root_path: Option<impl AsRef<Path>>,
    ) -> io::Result<PathBuf> {
        let path = self
            .validation
            .other_methods
            .get(&self.common_name)
            .map(|dom| {
                if let Some(path) = root_path {
                    let file_validation_url_http = dom
                        .file_validation_url_http
                        .replace("http://", "")
                        .replace(&self.common_name, "")
                        .trim_start_matches("/")
                        .to_string();

                    path.as_ref().join(file_validation_url_http).to_path_buf()
                } else {
                    PathBuf::from(&dom.file_validation_url_http)
                }
            })
            .ok_or(io::Error::new(
                ErrorKind::Other,
                "No file_validation url found on this struct, try to use build public method",
            ));

        if let Ok(ref ok_path) = path {
            if let Some(parent_path) = ok_path.parent() {
                if !parent_path.exists() {
                    fs::create_dir_all(parent_path)?;
                }
            }
        }

        path
    }

    pub(crate) fn validation_content(&self) -> String {
        self.validation
            .other_methods
            .get(&self.common_name)
            .map(|other| other.file_validation_content.join("\n"))
            .unwrap_or_default()
    }

    pub(crate) fn save_file_validation(&self, root_path: Option<&Path>) -> io::Result<()> {
        let mut fh = fs::File::options()
            .create(true)
            .write(true)
            .truncate(true)
            .open(self.validation_path_destination(root_path)?)?;

        let validation_content = self.validation_content();
        fh.write_all(validation_content.as_bytes())
    }
}

impl Display for ZeroSSLCreateCertificate {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        let string = serde_json::to_string(self).unwrap_or(format!("{self:?}"));
        write!(f, "{}", string)
    }
}

#[derive(Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub(crate) struct DomainVerificationResponse {
    pub(crate) success: bool,
}

#[derive(Default, Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct CertificatesFile {
    #[serde(rename = "certificate.crt")]
    pub(crate) certificate_crt: String,
    #[serde(rename = "ca_bundle.crt")]
    pub(crate) ca_bundle_crt: String,
}
