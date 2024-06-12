use super::error::Error;
use super::common::Curve;

pub trait CryptoAlgorithm<S: SecretKey<P>, P: PublicKey, SS: Signature> {
    fn generate_key() -> S;
    fn sign(key: &S, data: &[u8]) -> SS;
    fn verify(key: &P, data: &[u8], signature: &SS) -> bool;
}

pub trait PublicKey {
    fn as_bytes(&self) -> &[u8];
    fn from_bytes(b: &[u8]) -> Result<Self, Error> where Self: Sized;
    fn curve(&self) -> Curve;
}

pub trait SecretKey<P: PublicKey> {
    fn public_key(&self) -> P;
    fn as_bytes(&self) -> &[u8];
    fn from_bytes(b: &[u8]) -> Result<Self, Error> where Self: Sized;
    fn curve(&self) -> Curve;
}

pub trait Signature {}
