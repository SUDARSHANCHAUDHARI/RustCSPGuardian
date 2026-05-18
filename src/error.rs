use thiserror::Error;

#[derive(Error, Debug)]
#[allow(dead_code)]
pub enum CspGuardError {
    #[error("Invalid URL: {0}")]
    InvalidUrl(String),

    #[error("HTTP request failed: {0}")]
    RequestFailed(#[from] reqwest::Error),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}
