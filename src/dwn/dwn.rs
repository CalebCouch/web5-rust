use super::error::Error;
use super::common::{Signer, EciesEncryptor};
use super::records_write::{
    RecordsWrite,
    RecordsWriteOptions
};

use crate::dids::did_core::{DidUri, DidKey, Url};
use crate::dids::did_method::DidMethod;

use crate::crypto::traits;
use crate::crypto::traits::{DynCastExt as _};
use crate::crypto::LocalKeyStore;
use crate::common::traits::KeyValueStore;


const DEFAULT_ENDPOINTS: [&str; 1] = ["https://default.endpoint/"];

pub struct Dwn<D: DidMethod> {
    did: D,
    endpoints: Vec<Url>,
    signer: Signer,
    encryptor: EciesEncryptor
}

impl<D: DidMethod> Dwn<D> {
    pub fn from_did<KVS: KeyValueStore>(
        key_store: &mut LocalKeyStore<KVS>,
        did: D,
        endpoints: Option<Vec<Url>>,
        sig: Option<String>,
        enc: Option<String>
    ) -> Result<Self, Error> {
        let missing_key = |id| Error::Requires("The dwn".to_string(), format!("a key with id ({}) is present in the did", id));
        let missing_seckey = |pk| Error::Requires("The dwn".to_string(), format!("the secret key for public key ({}) can be found in the provided key store", pk));
        let not_sig_key = |id| Error::Requires("The dwn".to_string(), format!("the key with id ({}) is capable of signing", id));
        let not_enc_key = |id| Error::Requires("The dwn".to_string(), format!("the key with id ({}) is capable of encryption", id));
        let endpoints = endpoints.unwrap_or(DEFAULT_ENDPOINTS.iter().map(|e| Ok(Url::parse(e)?)).collect::<Result<Vec<Url>, Error>>()?);

        let sig = sig.unwrap_or("sig".to_string());
        let sig_pk = did.get_key(&sig).ok_or(missing_key(&sig))?.public_key();
        let sig_key: Box<dyn traits::SecretKey> = key_store.get_dyn_key(sig_pk)?.ok_or(missing_seckey(&hex::encode(sig_pk.to_vec())))?;
        let signing_key: Box<dyn traits::Signer> = sig_key.dyn_cast().or(Err(not_sig_key(&sig)))?;

        let enc = enc.unwrap_or("enc".to_string());
        let enc_pk: Box<dyn traits::PublicKey> = did.get_key(&enc).ok_or(missing_key(&enc))?.public_key().clone();
        let encryption_key: Box<dyn traits::EciesEncryptor> = enc_pk.dyn_cast().or(Err(not_enc_key(&enc)))?;

        let signer = Signer::new(signing_key, did.did().to_uri(None, None, Some(sig), None));
        let encryptor = EciesEncryptor::new(encryption_key, did.did().to_uri(None, None, Some(enc), None));

        Ok(Dwn{did, endpoints, signer, encryptor})
    }

    pub fn records_write(&self, data: &[u8]) -> Result<RecordsWrite, Error> {
        let dataSize = data.len();
        let options = RecordsWriteOptions{
            dataFormat: "application/json".to_string(),
            protocol: Some(Url::parse("https://areweweb5yet.com/protocols/social").unwrap()),
            protocolPath: Some("story".to_string()),
            schema: Some(Url::parse("https://areweweb5yet.com/protocols/social/schemas/story").unwrap()),
            published: Some(false),
            recipient: None,
            protocolRole: None,
            tags: None,
            recordId: None,
            parentContextId: None,
            data: Some(data.to_vec()),
            dataCid: None,
            dataSize: Some(dataSize),
            dateCreated: None,
            messageTimestamp: None,
            datePublished: None,
            signer: Some(self.signer.clone()),
            delegatedGrant: None,
            attestationSigners: Vec::new(),
            encryptionInput: None,
            permissionGrantId: None
        };
        Ok(RecordsWrite::create(options)?)
    }
}
