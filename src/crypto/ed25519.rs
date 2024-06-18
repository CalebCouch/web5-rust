use super::error::Error;
use super::common::Curve;
use super::traits;
use super::traits::AmbiguousKey as _;

use ed25519_dalek::{Signer, Verifier};
use ed25519_dalek::{Signature, VerifyingKey, SigningKey};
use jwtk::eddsa::{Ed25519PublicKey};
use jwtk::PublicKeyToJwk;
use cast_trait_object::{dyn_upcast, dyn_cast};
use serde::{Serialize, Deserialize, Serializer, Deserializer, de};

const ED25519: Curve = Curve::Ed;

#[derive(Clone, Copy, Debug, PartialEq, Deserialize, Serialize)]
pub struct PublicKey {
    key: VerifyingKey
}

impl traits::Curve for PublicKey {
    fn curve(&self) -> Curve { ED25519 }
}

impl traits::AmbiguousKey for PublicKey {
    fn from_bytes(b: &[u8]) -> Result<PublicKey, Error> {
        Ok(PublicKey{
            key: VerifyingKey::from_bytes(b.try_into()?)?
        })
    }

    fn to_vec(&self) -> Vec<u8> {
        self.key.to_bytes().to_vec()
    }
}

#[dyn_cast(traits::Verifier, traits::EciesEncryptor)]
#[dyn_upcast]
#[typetag::serde]
impl traits::PublicKey for PublicKey {
    fn thumbprint(&self) -> Result<String, Error> {
        let pk = Ed25519PublicKey::from_bytes(&self.to_vec())?;
        Ok(pk.public_key_to_jwk()?.get_thumbprint_sha256_base64()?)
    }
}

#[typetag::serde]
impl traits::Verifier for PublicKey {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, Error> {
        Ok(self.key.verify(data, &Signature::from_slice(signature)?).is_ok())
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct SecretKey {key: SigningKey}

impl traits::Curve for SecretKey {
    fn curve(&self) -> Curve { ED25519 }
}

impl traits::AmbiguousKey for SecretKey {
    fn from_bytes(b: &[u8]) -> Result<SecretKey, Error> {
        Ok(SecretKey{key: SigningKey::from_bytes(b.try_into()?)})
    }
    fn to_vec(&self) -> Vec<u8> {
        self.key.to_bytes().to_vec()
    }
}

#[dyn_cast(traits::Signer)]
#[dyn_upcast]
#[typetag::serde]
impl traits::SecretKey for SecretKey {
    fn generate_key() -> SecretKey {
        SecretKey{key: SigningKey::generate(&mut rand::rngs::OsRng)}
    }
    fn public_key(&self) -> Box<dyn traits::PublicKey> {
        Box::new(PublicKey{
            key: self.key.verifying_key()
        })
    }
}

#[typetag::serde]
impl traits::Signer for SecretKey {
    fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.key.sign(data).to_vec()
    }
}

impl Serialize for SecretKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error> where S: Serializer {
        serializer.serialize_bytes(&self.to_vec())
    }
}

impl<'de> de::Deserialize<'de> for SecretKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: de::Deserializer<'de>,
    {
        struct SecretKeyVisitor;

        impl<'de> de::Visitor<'de> for SecretKeyVisitor {
            type Value = SecretKey;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("SecretKey")
            }

            fn visit_bytes<E: de::Error>(self, bytes: &[u8]) -> Result<Self::Value, E> {
                Ok(Self::Value::from_bytes(bytes).or(Err(de::Error::custom::<String>("Invalid SecretKey Bytes".to_string())))?)
            }
        }

        deserializer.deserialize_bytes(SecretKeyVisitor {})
    }
}
