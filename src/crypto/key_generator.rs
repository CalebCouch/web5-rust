use super::jwk::Jwk;
use super::error::Error;

pub trait KeyGenerator<GenerateKeyInput, GenerateKeyOutput> {
    fn generate_key(params: GenerateKeyInput) -> impl std::future::Future<Output = Result<GenerateKeyOutput, Error>> + Send;
}

pub trait AsymmetricKeyGenerator<GenerateKeyInput, GenerateKeyOutput, GetPublicKeyInput>: KeyGenerator<GenerateKeyInput, GenerateKeyOutput> {
    //fn compute_public_key(params: GetPublicKeyInput) -> impl std::future::Future<Output = Result<Jwk, Error>> + Send;
    fn get_public_key(params: GetPublicKeyInput) -> impl std::future::Future<Output = Result<Jwk, Error>> + Send;
}
