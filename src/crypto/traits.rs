pub trait CryptoAlgorithm<SecretKey, PublicKey, Signature> {
    fn generate_key() -> SecretKey;
    fn sign(key: &SecretKey, data: &[u8]) -> Signature;
    fn verify(key: &PublicKey, data: &[u8], signature: &Signature) -> bool;
}

pub trait ToPublicKey<PublicKey> {
    fn public_key(&self) -> PublicKey;
}
