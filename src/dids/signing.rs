use super::Error;

use simple_crypto::{SecretKey, PublicKey, Hashable};

use crate::dids::structs::{
    DidKeyPair,
    Did,
};
use crate::dids::traits::DidResolver;

use simple_database::database::Index;
use simple_database::Indexable;

use serde::{Serialize, Deserialize};

use either::Either;

pub type Verifier = Either<Did, PublicKey>;
pub type Signer = Either<DidKeyPair, SecretKey>;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Signature{//TODO: add a time stamp to propery verify old rolled key signatures
    inner: Vec<u8>,
    signer: Verifier,
}

impl Signature {
    pub fn signer(&self) -> &Verifier {&self.signer}
    pub fn new(signer: Signer, payload: &[u8]) -> Self {
        match signer {
            Either::Left(keypair) => Signature{
                inner: keypair.secret.sign(payload),
                signer: Either::Left(keypair.public.key_uri().did()),
            },
            Either::Right(key) => Signature{
                inner: key.sign(payload),
                signer: Either::Right(key.public_key()),
            }
        }
    }

    pub fn verify_with_key(&self, key: &PublicKey, payload: &[u8]) -> Result<(), Error> {
        Ok(key.verify(payload, &self.inner)?)
    }

    pub async fn verify(&self, did_resolver: &dyn DidResolver, verifier: Option<&Verifier>, payload: &[u8]) -> Result<Verifier, Error> {
        let ec = "Signature.verify";
        let verifier = verifier.unwrap_or(&self.signer);
        if *verifier != self.signer {return Err(Error::auth_failed(ec, "Verifier did not match Signer"));}
        let dk = match &self.signer {
            Either::Left(did) => {
                did_resolver.resolve_dwn_keys(did).await?.0
            },
            Either::Right(key) => key.clone()
        };
        dk.verify(payload, &self.inner)?;
        Ok(verifier.clone())
    }
}

pub trait SignableObject: Clone + std::fmt::Debug {}
impl<O: Clone + std::fmt::Debug + Serialize + for<'a> Deserialize<'a>> SignableObject for O {}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct SignedObject<O: SignableObject> {
    signature: Signature,
    inner: O,
}

impl<O: SignableObject> Hashable for SignedObject<O> where O: Hashable + Serialize + for<'a> Deserialize<'a> {}

impl<O: SignableObject> SignedObject<O> where O: Serialize + for<'a> Deserialize<'a> {
    pub fn inner(&self) -> &O {&self.inner}
    pub fn unwrap(self) -> O {self.inner}
    pub fn signer(&self) -> &Verifier {self.signature.signer()}
    pub fn from_keypair(keypair: &DidKeyPair, inner: O) -> Result<Self, Error> {
        Self::new(Either::Left(keypair.clone()), inner)
    }
    pub fn from_key(key: &SecretKey, inner: O) -> Result<Self, Error> {
        Self::new(Either::Right(key.clone()), inner)
    }
    pub fn new(signer: Signer, inner: O) -> Result<Self, Error> {
        Ok(SignedObject{
            signature: Signature::new(signer, &serde_json::to_vec(&inner)?),
            inner,
        })
    }
    pub fn verify_with_key(self, key: &PublicKey) -> Result<O, Error> {
        self.signature.verify_with_key(key, &serde_json::to_vec(&self.inner)?)?;
        Ok(self.inner)
    }
    pub async fn verify(&self, did_resolver: &dyn DidResolver, verifier: Option<&Verifier>) -> Result<Verifier, Error> {
        self.signature.verify(did_resolver, verifier, &serde_json::to_vec(&self.inner)?).await
    }
}

impl<O: SignableObject> Indexable for SignedObject<O> where O: Indexable + Serialize + for<'a> Deserialize<'a> {
    const PRIMARY_KEY: &'static str = O::PRIMARY_KEY;
    const DEFAULT_SORT: &'static str = O::DEFAULT_SORT;
    fn primary_key(&self) -> Vec<u8> {self.inner.primary_key()}
    fn secondary_keys(&self) -> Index {
        let mut index = self.inner.secondary_keys();
        index.insert("signer".to_string(), self.signature.signer.to_string().into());
        index
    }
}

