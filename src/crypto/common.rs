use super::{ed25519, secp256k1, secp256r1};
use super::traits::{ToPublicKey};
use crate::common::traits::{FromStorageBytes, AsStorageBytes};
use crate::common::Error as CommonError;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Deserialize, Serialize)]
pub enum PublicKey {
    Ed(ed25519::PublicKey),
    K1(secp256k1::PublicKey),
    R1(secp256r1::PublicKey)
}

impl PublicKey {
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            PublicKey::Ed(key) => key.as_bytes(),
            PublicKey::K1(_key) => todo!(),
            PublicKey::R1(_key) => todo!()
        }
    }
}

impl AsStorageBytes for PublicKey {
    fn as_storage_bytes(&self) -> Result<Vec<u8>, CommonError> {
        Ok(self.as_bytes().to_vec())
    }
}

#[derive(Clone)]
pub enum SecretKey {
    Ed(ed25519::SecretKey),
    K1(secp256k1::SecretKey),
    R1(secp256r1::SecretKey)
}

impl SecretKey {
    pub fn public_key(&self) -> PublicKey {
        match self {
            SecretKey::Ed(key) => PublicKey::Ed(key.public_key()),
            SecretKey::K1(key) => PublicKey::K1(key.public_key()),
            SecretKey::R1(key) => PublicKey::R1(key.public_key()),
        }
    }
}

impl AsStorageBytes for SecretKey {
    fn as_storage_bytes(&self) -> Result<Vec<u8>, CommonError> {
        Ok(match self {
            SecretKey::Ed(key) => [vec![0], key.to_bytes().to_vec()].concat(),
            SecretKey::K1(_key) => todo!(),
            SecretKey::R1(_key) => todo!()
        })
    }
}

impl FromStorageBytes for SecretKey {
    fn from_storage_bytes(b: &[u8]) -> Result<Self, CommonError> {
        Ok(match b.first().ok_or(CommonError::FromStorageBytes())? {
            0 => SecretKey::Ed(ed25519::SecretKey::from_bytes(b[1..].try_into().or(Err(CommonError::FromStorageBytes()))?)),
            1 => todo!(),//SecretKey::K1(secp256k1::SecretKey::from_slice(&b[1..])?),
            2 => todo!(),
            _ => return Err(CommonError::FromStorageBytes())
        })
    }
}



#[derive(Clone)]
pub enum Signature {
    Ed(ed25519::Signature),
    K1(secp256k1::Signature),
    R1(secp256r1::Signature)
}
