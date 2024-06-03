use super::jwk::Jwk;

pub trait Signer {
    fn sign(key: Jwk, data: Vec<u8>) -> impl std::future::Future<Output = Vec<u8>> + Send;
    fn verify(key: Jwk, signature: Vec<u8>, data: Vec<u8>) -> impl std::future::Future<Output = bool> + Send;
}
