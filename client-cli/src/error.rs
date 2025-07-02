use thiserror::Error;

#[derive(Error, Debug)]
pub enum CliError {
    #[error("Invalid Ethereum private key: {0}")]
    InvalidPrivateKey(String),

    #[error("HTTP request failed: {0}")]
    HttpError(#[from] reqwest::Error),

    #[error("Authorization failed: {0}")]
    AuthorizationError(String),

    #[error("Invalid capability format: {0}")]
    InvalidCapability(String),

    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),

    #[error("Invalid DID format: {0}")]
    InvalidDid(String),

    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
}
