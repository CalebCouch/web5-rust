use super::error::Error;
use super::common::Curve as CurveS;
use cast_trait_object::{dyn_upcast, dyn_cast};
use downcast_rs::{impl_downcast, Downcast};
use std::fmt::Debug;

use dyn_clone::{clone_trait_object, DynClone};

pub use cast_trait_object::DynCastExt;

pub trait Curve {
    fn curve(&self) -> CurveS;
}

pub trait AmbiguousKey: Curve + Debug {
    fn from_bytes(b: &[u8]) -> Result<Self, Error> where Self: Sized;
    fn to_vec(&self) -> Vec<u8>;
}

#[dyn_cast(Verifier, EciesEncryptor)]
#[dyn_upcast]
#[typetag::serde(tag = "type")]
pub trait PublicKey: AmbiguousKey + Debug + DynClone + Downcast + Sync {
    fn thumbprint(&self) -> Result<String, Error>;
}
impl_downcast!(PublicKey);
clone_trait_object!(PublicKey);

#[typetag::serde(tag = "type")]
pub trait Verifier: PublicKey + Debug + DynClone {
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<bool, Error>;
}
clone_trait_object!(Verifier);

#[typetag::serde(tag = "type")]
pub trait EciesEncryptor: PublicKey + Debug + DynClone {
    fn ecies_encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error>;
}
clone_trait_object!(EciesEncryptor);

#[dyn_cast(Signer)]
#[dyn_upcast]
#[typetag::serde(tag = "type")]
pub trait SecretKey: AmbiguousKey + Debug + DynClone + Downcast {
    fn generate_key() -> Self where Self: Sized;
    fn public_key(&self) -> Box<dyn PublicKey>;
}
impl_downcast!(SecretKey);
clone_trait_object!(SecretKey);


#[typetag::serde(tag = "type")]
pub trait Signer: SecretKey + Debug + DynClone {
    fn sign(&self, data: &[u8]) -> Vec<u8>;
}
clone_trait_object!(Signer);
