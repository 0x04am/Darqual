use thiserror::Error;

#[derive(Debug, Error)]
pub enum Error {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("TOML serialization error: {0}")]
    TomlSer(#[from] toml::ser::Error),

    #[error("TOML deserialization error: {0}")]
    TomlDe(#[from] toml::de::Error),

    #[error("Encoding error: {0}")]
    Encoding(String),

    #[error("Decryption failed: wrong recipient or tampered ciphertext")]
    Decrypt,

    #[error("Invalid address: {0}")]
    InvalidAddress(String),

    #[error("Invalid contact card: {0}")]
    InvalidContactCard(String),

    #[error("Invalid lockbox: {0}")]
    InvalidLockbox(String),

    #[error("Key error: {0}")]
    Key(String),

    #[error("Identity already exists at {0} — use --force to overwrite")]
    IdentityExists(String),

    #[error("Ratchet error: {0}")]
    Ratchet(String),
}

pub type Result<T> = std::result::Result<T, Error>;
