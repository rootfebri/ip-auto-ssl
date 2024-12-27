use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub(crate) struct Args {
    #[arg(long, required = true, env = "ZEROSSL_ACCESS_KEY")]
    pub(crate) access_key: String,
    #[arg(short, long, required = true)]
    pub(crate) domain: String,
    #[arg(long, help = "default is /var/www/html", default_value = if cfg!(windows) { "." } else { "/var/www/html" })]
    pub(crate) public_html: PathBuf,
}
