use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid hex key/IV: {0}")]
    Hex(#[from] hex::FromHexError),

    #[error("PAT not found in transport stream")]
    PatNotFound,

    #[error("PMT not found for program {0}")]
    PmtNotFound(u16),

    #[error("Decryption error: {0}")]
    Decrypt(String),
}

pub type Result<T> = std::result::Result<T, Error>;
