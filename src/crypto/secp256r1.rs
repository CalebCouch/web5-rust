use super::traits::{CryptoAlgorithm, ToPublicKey};

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

impl ToPublicKey<PublicKey> for SecretKey {
    fn public_key(&self) -> PublicKey {
        todo!()
    }
}
