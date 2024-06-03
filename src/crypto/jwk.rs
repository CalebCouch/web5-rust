pub use jose_jwk::Jwk as jwk;
pub use jose_jwk::Key as KeyType;

use jose_b64::base64ct::{Base64Url, Encoding};

use super::error::Error;

//  pub fn compute_jwk_thumbprint(jwk: &Jwk) -> Result<Vec<u8>, Error> {
//      Ok(jwk.prm.x5t.s256.clone().ok_or(Error::NoThumbprint())?.to_vec())
//  }

pub struct Jwk{}

impl Jwk {
    pub fn get_public_bytes(jwk: &Jwk) -> Result<Vec<u8>, Error> {
        match jwk.key {
            Okp(key) => { //Ed25519
                let mut enc_buf = [0u8; 128];
                Ok(Base64Url::encode(&key.x, &mut enc_buf)?)
            }
        }
    }

    pub fn get_private_bytes(jwk: &Jwk) -> Result<Vec<u8>, Error> {
        match jwk.key {
            Okp(key) => { //Ed25519
                let mut enc_buf = [0u8; 128];
                Ok(Base64Url::encode(&key.d.ok_or(Error::NotSecretJwk())?, &mut enc_buf)?)
            }
        }
    }
}
