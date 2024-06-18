use super::error::Error;

use crate::crypto::traits;
use crate::dids::did_core::{DidUri};
use crate::crypto::traits::{Signer as _};
use crate::crypto::common::Curve;

use serde::{Serialize};

#[derive(Debug, Clone, Serialize)]
pub struct Signer {
    key: Box<dyn traits::Signer>,
    key_uri: DidUri
}

impl Signer {
    pub fn key_uri(&self) -> &DidUri { &self.key_uri }

    pub fn new(key: Box<dyn traits::Signer>, key_uri: DidUri) -> Self {
        Signer{key, key_uri}
    }

    pub fn sign(&self, data: &[u8]) -> Vec<u8> {
        self.key.sign(data)
    }
}

impl traits::Curve for Signer {
    fn curve(&self) -> Curve { self.key.curve() }
}

#[derive(Debug, Clone, Serialize)]
pub struct EciesEncryptor {
    key: Box<dyn traits::EciesEncryptor>,
    key_uri: DidUri
}

impl EciesEncryptor {
    pub fn key_uri(&self) -> &DidUri { &self.key_uri }

    pub fn new(key: Box<dyn traits::EciesEncryptor>, key_uri: DidUri) -> Self {
        EciesEncryptor{key, key_uri}
    }

    pub fn ecies_encrypt(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        Ok(self.key.ecies_encrypt(data)?)
    }
}

impl traits::Curve for EciesEncryptor {
    fn curve(&self) -> Curve { self.key.curve() }
}
