use super::error::Error;
use super::{ed25519, secp256k1, secp256r1};
use serde::{Deserialize, Serialize};
use super::traits::PublicKey;

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum Curve { Ed, K1, R1 }

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum GenericPublicKey {
    Ed(ed25519::PublicKey),
    K1(secp256k1::PublicKey),
    R1(secp256r1::PublicKey)
}

impl GenericPublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            Self::Ed(key) => key.as_bytes(),
            Self::K1(key) => key.as_bytes(),
            Self::R1(key) => key.as_bytes(),
        }
    }
    pub fn from_bytes(c: Curve, b: &[u8]) -> Result<Self, Error> where Self: Sized {
        Ok(match c {
            Curve::Ed => Self::Ed(PublicKey::from_bytes(b)?),
            Curve::K1 => Self::K1(PublicKey::from_bytes(b)?),
            Curve::R1 => Self::R1(PublicKey::from_bytes(b)?)
        })
    }
    pub fn curve(&self) -> Curve {
        match self {
            Self::Ed(key) => key.curve(),
            Self::K1(key) => key.curve(),
            Self::R1(key) => key.curve(),
        }
    }
}

#[derive(Clone)]
pub enum GenericSecretKey {
    Ed(ed25519::SecretKey),
    K1(secp256k1::SecretKey),
    R1(secp256r1::SecretKey)
}

#[derive(Clone)]
pub enum GenericSignature {
    Ed(ed25519::Signature),
    K1(secp256k1::Signature),
    R1(secp256r1::Signature)
}
