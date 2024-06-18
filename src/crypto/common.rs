use serde::{Deserialize, Serialize};
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Deserialize, Serialize)]
pub enum Curve { Ed, K1, R1 }

impl Curve {
    pub fn to_jose_alg(&self) -> String {
        //'P-384'     : 'ES384',
        //'P-521'     : 'ES512',
        match self {
            Self::Ed => "EdDSA",
            Self::K1 => "ES256K",
            Self::R1 => "ES256",
        }.to_string()
    }

    pub fn supports_ecies(&self) -> bool {
        match self {
            Self::Ed => false,
            Self::K1 => true,
            Self::R1 => false
        }
    }

    pub fn supports_signing(&self) -> bool {
        match self {
            Self::Ed => true,
            Self::K1 => true,
            Self::R1 => true
        }
    }
}

impl fmt::Display for Curve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", match self {
            Self::Ed => "Ed25519",
            Self::K1 => "Secp256k1",
            Self::R1 => "Secp256r1"
        })
    }
}
