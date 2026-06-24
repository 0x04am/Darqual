use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};

use crate::address::DarqualAddress;
use crate::error::{Error, Result};

const CARD_PREFIX: &str = "dqcard1";

/// A shareable contact card: address + ed25519 public key + x25519 public key.
/// Self-authenticating: the address is derived from ed_pub.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContactCard {
    pub address: DarqualAddress,
    pub ed_pub: [u8; 32],
    pub x_pub: [u8; 32],
}

/// Wire format for serialization (base32-encoded fields).
#[derive(Serialize, Deserialize)]
struct ContactCardWire {
    address: String,
    ed_pub: String,
    x_pub: String,
}

impl ContactCard {
    pub fn new(address: DarqualAddress, ed_pub: [u8; 32], x_pub: [u8; 32]) -> Self {
        ContactCard {
            address,
            ed_pub,
            x_pub,
        }
    }

    /// Verify that the address is correctly derived from ed_pub.
    pub fn verify(&self) -> bool {
        let expected = DarqualAddress::from_keys(&self.ed_pub, &self.x_pub);
        self.address == expected
    }

    /// Encode to a shareable string: "dqcard1" + base32(toml_bytes)
    fn encode(&self) -> String {
        let wire = ContactCardWire {
            address: self.address.to_string(),
            ed_pub: hex::encode(self.ed_pub),
            x_pub: hex::encode(self.x_pub),
        };
        let toml_str = toml::to_string(&wire).expect("ContactCard serialization is infallible");
        let encoded = BASE32_NOPAD.encode(toml_str.as_bytes()).to_lowercase();
        format!("{}{}", CARD_PREFIX, encoded)
    }

    /// Parse from a shareable string.
    fn decode(s: &str) -> Result<Self> {
        let lower = s.to_lowercase();
        if !lower.starts_with(CARD_PREFIX) {
            return Err(Error::InvalidContactCard(format!(
                "missing '{}' prefix",
                CARD_PREFIX
            )));
        }
        let body = &lower[CARD_PREFIX.len()..];
        let bytes = BASE32_NOPAD
            .decode(body.to_uppercase().as_bytes())
            .map_err(|e| Error::InvalidContactCard(format!("base32 decode: {}", e)))?;
        let toml_str = std::str::from_utf8(&bytes)
            .map_err(|e| Error::InvalidContactCard(format!("utf8: {}", e)))?;
        let wire: ContactCardWire = toml::from_str(toml_str)
            .map_err(|e| Error::InvalidContactCard(format!("toml: {}", e)))?;

        let address = wire.address.parse::<DarqualAddress>()?;
        let ed_pub = decode_hex_32(&wire.ed_pub)?;
        let x_pub = decode_hex_32(&wire.x_pub)?;

        Ok(ContactCard {
            address,
            ed_pub,
            x_pub,
        })
    }
}

impl std::fmt::Display for ContactCard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.encode())
    }
}

impl std::str::FromStr for ContactCard {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::decode(s)
    }
}

fn decode_hex_32(s: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(s).map_err(|e| Error::Encoding(format!("hex decode: {}", e)))?;
    bytes
        .try_into()
        .map_err(|_| Error::InvalidContactCard("expected 32-byte key".to_string()))
}
