use super::error::Error;
use super::common::Curve;
use super::traits::CryptoAlgorithm;
use super::traits;

use rand::rngs::OsRng;
use p256::ecdsa::signature::{Signer, Verifier};
pub use p256::ecdsa::SigningKey as SecretKey;
pub use p256::ecdsa::VerifyingKey as PublicKey;
pub use p256::ecdsa::Signature;

pub struct Secp256r1 {}

impl CryptoAlgorithm<SecretKey, PublicKey, Signature> for Secp256r1 {
    fn generate_key() -> SecretKey {
        let mut csprng = OsRng;
        SecretKey::random(&mut csprng)
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
    fn from_bytes(_b: &[u8]) -> Result<PublicKey, Error> {
        todo!()
    }
    fn curve(&self) -> Curve { Curve::R1 }
}

impl traits::SecretKey<PublicKey> for SecretKey {
    fn public_key(&self) -> PublicKey {
        *self.verifying_key()
    }
    fn as_bytes(&self) -> &[u8] {
        todo!()
    }
    fn from_bytes(_b: &[u8]) -> Result<SecretKey, Error> {
        todo!()
    }
    fn curve(&self) -> Curve { Curve::R1 }
}

impl traits::Signature for Signature {}
