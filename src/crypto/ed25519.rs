use super::Error;

use crate::common::Convert;

use ed25519_dalek::{Signature, VerifyingKey, SigningKey};
use ed25519_dalek::{Signer, Verifier};
use serde::{Serialize, Deserialize};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct PublicKey {
    key: VerifyingKey
}

impl PublicKey {
    pub fn to_vec(&self) -> Vec<u8> {
        self.key.to_bytes().to_vec()
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self, Error> {
        Ok(PublicKey{
            key: VerifyingKey::from_bytes(b.try_into()?)?
        })

    }
    pub fn thumbprint(&self) -> String {
        Convert::ZBase32.encode(self.key.as_bytes())
    }

    pub fn verify(&self, payload: &[u8], signature: &[u8]) -> Result<bool, Error> {
        Ok(self.key.verify(payload, &Signature::from_slice(signature)?).is_ok())
    }
}

impl std::fmt::Display for PublicKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.thumbprint())
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct SecretKey {
    key: SigningKey
}

impl SecretKey {
    pub fn new() -> Self {
        SecretKey{key: SigningKey::generate(&mut rand::rngs::OsRng)}
    }
    pub fn sign(&self, payload: &[u8]) -> Vec<u8> {
        self.key.sign(payload).to_vec()
    }
    pub fn public_key(&self) -> PublicKey {
        PublicKey{key: self.key.verifying_key()}
    }
}

impl Default for SecretKey {
    fn default() -> Self {Self::new()}
}

impl std::fmt::Display for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.public_key().thumbprint())
    }
}
