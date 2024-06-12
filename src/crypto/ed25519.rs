use super::error::Error;
use super::common::Curve;
use super::traits::CryptoAlgorithm;
use super::traits;

use rand::rngs::OsRng;

use ed25519_dalek::{Signer, Verifier};
pub use ed25519_dalek::SigningKey as SecretKey;
pub use ed25519_dalek::VerifyingKey as PublicKey;
pub use ed25519_dalek::Signature;

pub struct Ed25519 {}

impl CryptoAlgorithm<SecretKey, PublicKey, Signature> for Ed25519 {
    fn generate_key() -> SecretKey {
        let mut csprng = OsRng;
        SecretKey::generate(&mut csprng)
    }

    fn sign(key: &SecretKey, data: &[u8]) -> Signature {
        key.sign(data)
    }

    fn verify(key: &PublicKey, data: &[u8], signature: &Signature) -> bool {
        key.verify(data, signature).is_ok()
    }
}

impl traits::PublicKey for PublicKey {
    fn as_bytes(&self) -> &[u8] {
        todo!()
    }
    fn from_bytes(b: &[u8]) -> Result<PublicKey, Error> {
        Ok(PublicKey::from_bytes(b.try_into()?)?)
    }
    fn curve(&self) -> Curve { Curve::Ed }
}

impl traits::SecretKey<PublicKey> for SecretKey {
    fn public_key(&self) -> PublicKey {
        self.verifying_key()
    }
    fn as_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
    fn from_bytes(b: &[u8]) -> Result<SecretKey, Error> {
        Ok(SecretKey::from_bytes(b.try_into()?))
    }
    fn curve(&self) -> Curve { Curve::Ed }
}

impl traits::Signature for Signature {}
