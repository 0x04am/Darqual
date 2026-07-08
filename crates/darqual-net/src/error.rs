use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Frame too large: {0} bytes (max 16 MiB)")]
    FrameTooLarge(u32),

    #[error("Frame encoding error: {0}")]
    Encoding(String),
}

pub type Result<T> = std::result::Result<T, Error>;
