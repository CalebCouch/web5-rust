use super::traits::{CryptoAlgorithm, ToPublicKey};

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

impl ToPublicKey<PublicKey> for SecretKey {
    fn public_key(&self) -> PublicKey {
        self.verifying_key()
    }
}
