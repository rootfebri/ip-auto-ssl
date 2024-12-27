use crate::zero_ssl::{CertSignReq, CreateZeroSSLCertificate};
use clap::Parser;
use std::env::set_var;
use std::io::{ErrorKind, Write};
use std::path::Path;
use std::{fs, io};

mod args;
pub(crate) mod zero_ssl;

pub(crate) use args::*;

pub(crate) fn cv_err(error: impl std::error::Error + Send + Sync + 'static) -> io::Error {
    io::Error::new(ErrorKind::Other, error)
}

pub(crate) static API: &str = "https://api.zerossl.com";
pub(crate) fn force_write<P: AsRef<Path>>(p: P, buf: &[u8]) -> io::Result<()> {
    fs::File::options()
        .create(true)
        .write(true)
        .truncate(true)
        .open(p)?
        .write_all(buf)
}

#[tokio::main]
async fn main() -> io::Result<()> {
    dotenv::dotenv().ok();
    if !cfg!(debug_assertions) {
        set_var("RUST_BACKTRACE", "");
    }

    let args = Args::parse();
    let create_zsl_cert = CreateZeroSSLCertificate::new(&args.domain);
    let csr = CertSignReq::default();

    let zsl = create_zsl_cert.create(&csr).await?;

    println!("{}", zsl);
    println!("{:?}", zsl);

    zsl.save_file_validation(Some(args.public_html.as_path()))
        .expect("Failedd to save file validation");
    create_zsl_cert.verify(&zsl).await?;

    let certificates = create_zsl_cert.certificate(&zsl).await?;
    force_write(
        format!("{}.crt", args.domain),
        certificates.certificate_crt.as_bytes(),
    )?;
    force_write(
        format!("{}.ca-bundle.crt", args.domain),
        certificates.ca_bundle_crt.as_bytes(),
    )?;
    force_write(
        format!("{}.key", args.domain),
        csr.key_pair.serialize_pem().as_bytes(),
    )?;

    Ok(())
}
