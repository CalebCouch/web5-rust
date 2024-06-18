use super::error::Error;
use crate::dids::did_core::{DidUri, Url, Did};
use crate::crypto::common::Curve;
use crate::common::Convert;
use super::common::Signer;

use chrono::prelude::*;

use std::collections::HashMap;

use crate::crypto::secp256k1;
use crate::crypto::traits;
use crate::crypto::traits::{PublicKey as _, Curve as _};

use unixfs_v1::file::adder::{Chunker, FileAdderBuilder};
use std::fmt;

use libipld::cid;

use cid::multihash::MultihashDigest;

use serde::{Serialize, Deserialize, Serializer};
use serde::ser::SerializeStruct;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignatureEntry {
  protected: ProtectedHeader,
  signature: String
}

impl SignatureEntry {
    pub fn get_signer(&self) -> Did {
        self.protected.kid.did()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct ProtectedHeader {
  kid: DidUri,
  alg: String
}

impl Serialize for ProtectedHeader {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("protectedHeader", 2)?;
        state.serialize_field("kid", &self.kid.to_string())?;
        state.serialize_field("alg", &self.alg)?;
        state.end()
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct SignaturePayload {
    descriptorCid: String,

    recordId: Option<String>,
    contextId: Option<String>,
    protocolRole: Option<String>,
    encryptionCid: Option<String>,
    attestationCid: Option<String>,
    delegatedGrantId: Option<String>,
    permissionGrantId: Option<String>
}

impl SignaturePayload {
    pub fn attestationPayload(descriptorCid: String) -> Self {
        SignaturePayload{
            descriptorCid,

            recordId: None,
            contextId: None,
            protocolRole: None,
            attestationCid: None,
            delegatedGrantId: None,
            permissionGrantId: None,
            encryptionCid: None
        }
    }
}

impl Serialize for SignaturePayload {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut fields = 1;
        if self.recordId.is_some() { fields += 1; }
        if self.contextId.is_some() { fields += 1; }
        if self.protocolRole.is_some() { fields += 1; }
        if self.attestationCid.is_some() { fields += 1; }
        if self.delegatedGrantId.is_some() { fields += 1; }
        if self.permissionGrantId.is_some() { fields += 1; }
        if self.encryptionCid.is_some() { fields += 1; }

        let mut state = serializer.serialize_struct("signaturePayload", fields)?;
        if let Some(i) = &self.recordId { state.serialize_field("recordId", &i)? };
        state.serialize_field("descriptorCid", &self.descriptorCid)?;
        if let Some(i) = &self.contextId { state.serialize_field("contextId", &i)? };
        if let Some(i) = &self.protocolRole { state.serialize_field("protocolRole", &i)? };
        if let Some(i) = &self.attestationCid { state.serialize_field("attestationCid", &i)? };
        if let Some(i) = &self.permissionGrantId { state.serialize_field("permissionGrantId", &i)? };
        if let Some(i) = &self.encryptionCid { state.serialize_field("encryptionCid", &i)? };
        state.end()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralJws {
  payload: SignaturePayload,
  signatures: Vec<SignatureEntry>
}

impl GeneralJws {
    pub fn create(payload: SignaturePayload, signers: Vec<Signer>) -> Result<Self, Error> {
        if signers.is_empty() { return Err(Error::Dependant("GeneralJws::create".to_string(), "at least one signer".to_string())); } //TODO: Might be too strict

        let mut jws = GeneralJws{
          payload,
          signatures : Vec::new()
        };

        for signer in signers {
            jws.addSignature(signer);
        }

        Ok(jws)
    }

    pub fn addSignature(&mut self, signer: Signer) -> Result<(), Error> {
        let protectedHeader = ProtectedHeader{
            kid: signer.key_uri().clone(),
            alg: signer.curve().to_jose_alg()
        };

        let protected = Convert::Base64UrlUnpadded.encode(&serde_json::to_vec(&protectedHeader)?);
        let payload = Convert::Base64UrlUnpadded.encode(&serde_json::to_vec(&self.payload)?);
        let sig_input = format!("{}.{}", protected, payload).into_bytes();
        let signature = Convert::Base64UrlUnpadded.encode(&signer.sign(&sig_input).to_vec());
        self.signatures.push(SignatureEntry{protected: protectedHeader, signature});
        Ok(())
    }

    pub fn first_signature(&self) -> &SignatureEntry {
        &self.signatures.first().as_ref().unwrap()
    }
    pub fn payload(&self) -> &SignaturePayload {
        &self.payload
    }
    pub fn get_signer(&self) -> Did {
        self.first_signature().get_signer()
    }
}

//pub type RecordsWriteTags = HashMap<String, Vec<String>>;

//  pub struct Signer {
//    key_uri: DidUri,
//    algorithm: String,
//    sign: Box<dyn Fn(&[u8]) -> Vec<u8>>
//  }

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum KeyDerivationScheme {
  DataFormats, // = 'dataFormats',
  ProtocolContext, // = 'protocolContext',
  ProtocolPath, // = 'protocolPath',
  Schemas, // = 'schemas'
}

impl fmt::Display for KeyDerivationScheme {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f,"{}", match self {
            Self::DataFormats => "dataFormats",
            Self::ProtocolContext => "protocolContext",
            Self::ProtocolPath => "protocolPath",
            Self::Schemas => "schemas"
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
  Aes256Ctr, // = 'A256CTR',
  EciesSecp256k1 // = 'ECIES-ES256K'
}

#[derive(Debug, Clone, Serialize)]
pub struct EncryptedKey {
  rootKeyUri: DidUri,
  derivedPublicKey: Option<Box<dyn traits::EciesEncryptor>>,
  derivationScheme: KeyDerivationScheme,
  algorithm: EncryptionAlgorithm,
  initializationVector: String,
  ephemeralPublicKey: Box<dyn traits::PublicKey>, //TODO be more strict with what this key is capable of
  messageAuthenticationCode: String,
  encryptedKey: String
}

#[derive(Debug, Clone, Serialize)]
pub struct EncryptionProperty {
  algorithm: EncryptionAlgorithm,
  initializationVector: String,
  keyEncryption: Vec<EncryptedKey>
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DwnInterfaceName {
  Events, // = 'Events',
  Messages, // = 'Messages',
  Protocols, // = 'Protocols',
  Records // = 'Records'
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DwnMethodName {
  Configure, // = 'Configure',
  Create, // = 'Create',
  Get, // = 'Get',
  Grant, // = 'Grant',
  Query, // = 'Query',
  Read, // = 'Read',
  Request, // = 'Request',
  Revoke, // = 'Revoke',
  Write, // = 'Write',
  Delete, // = 'Delete',
  Subscribe // = 'Subscribe'
}

//DelegatedGrantRecordsWriteMessage.authorization



pub struct EncryptionInput {
  algorithm: Option<EncryptionAlgorithm>,
  initializationVector: Vec<u8>,
  key: Vec<u8>,
  keyEncryptionInputs: Vec<KeyEncryptionInput>
}

pub struct KeyEncryptionInput {
  derivationScheme: KeyDerivationScheme,
  publicKeyId: DidUri,
  publicKey: Box<dyn traits::EciesEncryptor>,
  algorithm: Option<EncryptionAlgorithm>
}

pub struct RecordsWriteOptions {
    pub dataFormat: String,

    pub recipient: Option<String>,
    pub protocol: Option<Url>,
    pub protocolPath: Option<String>,
    pub protocolRole: Option<String>,
    pub schema: Option<Url>,
    pub tags: Option<HashMap<String, Vec<String>>>,
    pub recordId: Option<String>,
    pub parentContextId: Option<String>,
    pub data: Option<Vec<u8>>,
    pub dataCid: Option<String>,
    pub dataSize: Option<usize>,
    pub dateCreated: Option<String>,
    pub messageTimestamp: Option<String>,
    pub published: Option<bool>,
    pub datePublished: Option<String>,
    pub signer: Option<Signer>,
    pub delegatedGrant: Option<DelegatedGrant>,
    pub attestationSigners: Vec<Signer>,
    pub encryptionInput: Option<EncryptionInput>,
    pub permissionGrantId: Option<String>
}



pub struct GenericSignaturePayload {
  descriptorCid: String,
  permissionGrantId: Option<String>,
  delegatedGrantId: Option<String>,
  protocolRole: Option<String>
}

//  pub trait MessageInterface {
//    fn get_message() -> GenericMessage;
//    fn get_signer() -> Option<String>;
//    fn get_author() -> Option<String>;
//    fn get_signaturePayload() -> Option<GenericSignaturePayload>;
//  }

pub struct Cid {}

impl Cid {

    pub fn dagcbor_cid(content: &[u8]) -> String {
        cid::Cid::new_v1(0x71, cid::multihash::Code::Sha2_256.digest(content)).to_string()
    }

    pub fn dagpb_cid(content: &[u8]) -> String {
        let mut fileAdder = FileAdderBuilder::default()
            .with_chunker(Chunker::Size(256 * 1024))
            .build();
        fileAdder.push(content);
        let mut blocks: Vec<(libipld::cid::Cid, Vec<u8>)> = fileAdder.finish().collect();
        blocks.pop().map(|(c, _)| c.to_string()).unwrap_or("".to_string())
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Descriptor {
    interface: DwnInterfaceName,
    method: DwnMethodName,
    messageTimestamp: String,
    protocol: Option<Url>,
    protocolPath: Option<String>,
    recipient: Option<String>,
    schema: Option<Url>,
    parentId: Option<String>,
    dataCid: Option<String>,
    dataSize: Option<usize>,
    dateCreated: Option<String>,
    published: Option<bool>,
    datePublished: Option<String>,
    dataFormat: Option<String>,
    tags: Option<HashMap<String, Vec<String>>>
}

impl Serialize for Descriptor {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut fields = 3;
        if self.protocol.is_some() { fields += 1; }
        if self.protocolPath.is_some() { fields += 1; }
        if self.recipient.is_some() { fields += 1; }
        if self.schema.is_some() { fields += 1; }
        if self.parentId.is_some() { fields += 1; }
        if self.dataCid.is_some() { fields += 1; }
        if self.dataSize.is_some() { fields += 1; }
        if self.dateCreated.is_some() { fields += 1; }
        if self.published.is_some() { fields += 1; }
        if self.datePublished.is_some() { fields += 1; }
        if self.dataFormat.is_some() { fields += 1; }
        if self.tags.is_some() { fields += 1; }

        let mut state = serializer.serialize_struct("descriptor", fields)?;
        state.serialize_field("interface", &self.interface)?;
        state.serialize_field("method", &self.method)?;
        state.serialize_field("messageTimestamp", &self.messageTimestamp)?;
        if let Some(i) = &self.protocol { state.serialize_field("protocol", &i)? };
        if let Some(i) = &self.protocolPath { state.serialize_field("protocolPath", &i)? };
        if let Some(i) = &self.recipient { state.serialize_field("recipient", &i)? };
        if let Some(i) = &self.schema { state.serialize_field("schema", &i)? };
        if let Some(i) = &self.parentId { state.serialize_field("parentId", &i)? };
        if let Some(i) = &self.dataCid { state.serialize_field("dataCid", &i)? };
        if let Some(i) = &self.dataSize { state.serialize_field("dataSize", &i)? };
        if let Some(i) = &self.dateCreated { state.serialize_field("dateCreated", &i)? };
        if let Some(i) = &self.published { state.serialize_field("published", &i)? };
        if let Some(i) = &self.datePublished { state.serialize_field("datePublished", &i)? };
        if let Some(i) = &self.dataFormat { state.serialize_field("dataFormat", &i)? };
        if let Some(i) = &self.tags { state.serialize_field("tags", &i)? }
        state.end()
    }
}

pub struct EntryIdInput {
    descriptor: Descriptor,
    author: Did
}

impl Serialize for EntryIdInput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut fields = 4;
        if self.descriptor.protocol.is_some() { fields += 1; }
        if self.descriptor.protocolPath.is_some() { fields += 1; }
        if self.descriptor.recipient.is_some() { fields += 1; }
        if self.descriptor.schema.is_some() { fields += 1; }
        if self.descriptor.parentId.is_some() { fields += 1; }
        if self.descriptor.dataCid.is_some() { fields += 1; }
        if self.descriptor.dataSize.is_some() { fields += 1; }
        if self.descriptor.dateCreated.is_some() { fields += 1; }
        if self.descriptor.published.is_some() { fields += 1; }
        if self.descriptor.datePublished.is_some() { fields += 1; }
        if self.descriptor.dataFormat.is_some() { fields += 1; }
        if self.descriptor.tags.is_some() { fields += 1; }

        let mut state = serializer.serialize_struct("descriptor", fields)?;
        state.serialize_field("author", &self.author.to_string())?;
        state.serialize_field("interface", &self.descriptor.interface)?;
        state.serialize_field("method", &self.descriptor.method)?;
        state.serialize_field("messageTimestamp", &self.descriptor.messageTimestamp)?;
        if let Some(i) = &self.descriptor.protocol { state.serialize_field("protocol", &i)? };
        if let Some(i) = &self.descriptor.protocolPath { state.serialize_field("protocolPath", &i)? };
        if let Some(i) = &self.descriptor.recipient { state.serialize_field("recipient", &i)? };
        if let Some(i) = &self.descriptor.schema { state.serialize_field("schema", &i)? };
        if let Some(i) = &self.descriptor.parentId { state.serialize_field("parentId", &i)? };
        if let Some(i) = &self.descriptor.dataCid { state.serialize_field("dataCid", &i)? };
        if let Some(i) = &self.descriptor.dataSize { state.serialize_field("dataSize", &i)? };
        if let Some(i) = &self.descriptor.dateCreated { state.serialize_field("dateCreated", &i)? };
        if let Some(i) = &self.descriptor.published { state.serialize_field("published", &i)? };
        if let Some(i) = &self.descriptor.datePublished { state.serialize_field("datePublished", &i)? };
        if let Some(i) = &self.descriptor.dataFormat { state.serialize_field("dataFormat", &i)? };
        if let Some(i) = &self.descriptor.tags { state.serialize_field("tags", &i)? }
        state.end()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DelegatedGrant {
    descriptor: Descriptor,
    signature: GeneralJws,

    recordId: Option<String>,
    contextId: Option<String>,
}

#[derive(Debug)]
pub struct AuthorizationModel {
  signature: GeneralJws,
  authorDelegatedGrant: Option<DelegatedGrant>,
  ownerSignature: Option<GeneralJws>,
  ownerDelegatedGrant: Option<DelegatedGrant>
}

#[derive(Debug)]
pub struct RecordsWriteMessage {
    descriptor: Descriptor,
    authorization: Option<AuthorizationModel>,

    recordId: Option<String>,
    contextId: Option<String>,
    attestation: Option<GeneralJws>,
    encryption: Option<EncryptionProperty>
}

#[derive(Debug)]
pub struct RecordsWrite {
    parentContextId: Option<String>,
    message: RecordsWriteMessage,
    author: Option<Did>,
    signaturePayload: Option<SignaturePayload>,
    owner: Option<Did>,
    ownerSignaturePayload: Option<SignaturePayload>,
    attesters: Vec<Did>
}

impl RecordsWrite {
    fn getRecordIdFromContextId(contextId: &Option<String>) -> Option<String> {
        return contextId.as_ref().map(|c| c.split('/').filter(|s| !s.is_empty()).collect::<Vec<&str>>().pop().map(|p| p.to_string())).flatten();
    }

    pub fn createAttestation(descriptorCid: String, signers: Vec<Signer>) -> Result<Option<GeneralJws>, Error> {
        if signers.is_empty() { return Ok(None); }
        Ok(Some(GeneralJws::create(SignaturePayload::attestationPayload(descriptorCid), signers)?))
    }

    fn createEncryptionProperty(
        descriptor: &Descriptor,
        encryption_input: Option<EncryptionInput>
    ) -> Result<Option<EncryptionProperty>, Error> {
        let ei = if let Some(encryption_input) = encryption_input { encryption_input } else { return Ok(None); };

        // encrypt the data encryption key once per encryption input
        let keyEncryption: Vec<EncryptedKey> = ei.keyEncryptionInputs.iter().map(|kei| {
            if kei.derivationScheme == KeyDerivationScheme::ProtocolPath && descriptor.protocol.is_none() {
                return Err(Error::Dependant(KeyDerivationScheme::ProtocolPath.to_string(), "descriptor.protocol".to_string()));
            }
            if kei.derivationScheme == KeyDerivationScheme::Schemas && descriptor.schema.is_none() {
                return Err(Error::Dependant(KeyDerivationScheme::Schemas.to_string(), "descriptor.schema".to_string()));
            }

            todo!();
            //let _ec = kei.publicKey.ecies_encrypt(&ei.key)?;
            //TODO initializationVector/messageAuthenticationCode are variables that need to be derived from the encrypt result
            // ec currently contains the ephemeralKey followed by the encryptedKey
          //Ok(EncryptedKey{
          //    rootKeyUri: kei.publicKeyId,
          //    derivedPublicKey: if kei.derivationSchema == KeyDerivationScheme::ProtocolContext {Some(kei.publicKey)} else {None},
          //    derivationScheme: kei.keyDerivationScheme,
          //    algorithm: kei.algorithm.unwrap_or(EncryptionAlgorithm::EciesSecp256k1),
          //    initializationVector: String::new(), //TODO
          //    ephemeralPublicKey: GenericPublicKey::from_bytes(Curve::K1, ec[..65])?,
          //    messageAuthenticationCode: String::new(), //TODO
          //    encryptedKey: Convert::Base64Url.encode(ec[65..])
          //})
        }).collect::<Result<Vec<EncryptedKey>, Error>>()?;

        Ok(Some(EncryptionProperty{
            algorithm            : ei.algorithm.unwrap_or( EncryptionAlgorithm::Aes256Ctr),
            initializationVector : Convert::Base64Url.encode(&ei.initializationVector),
            keyEncryption
        }))
    }

    pub fn getAttesters(message: &RecordsWriteMessage) -> Vec<Did> {
        if let Some(attestation) = &message.attestation {
            attestation.signatures.iter().map(|s| s.get_signer()).collect()
        } else {Vec::new()}
    }

    fn new(message: RecordsWriteMessage, parentContextId: Option<String>) -> Self {
        let (author, signaturePayload, owner, ownerSignaturePayload) =
            if let Some(authorization) = &message.authorization {
                let a = match &authorization.authorDelegatedGrant {
                    Some(adg) => Some(adg.signature.get_signer()),
                    None => message.authorization.as_ref().map(|a| a.signature.get_signer())
                };

                let sp = authorization.signature.payload().clone();

                let (o, osp) = if let Some(os) = &authorization.ownerSignature {
                    let o: Did = match &authorization.ownerDelegatedGrant {
                        Some(odg) => odg.signature.get_signer(),
                        None => os.get_signer()
                    };

                    (Some(o), Some(os.payload().clone()))
                } else {(None, None)};

                (a, Some(sp), o, osp)
            } else {(None, None, None, None)};

        let attesters = RecordsWrite::getAttesters(&message);
        RecordsWrite{
            parentContextId,
            message,
            author,
            signaturePayload,
            owner,
            ownerSignaturePayload,
            attesters
        }
    }

    pub fn create(options: RecordsWriteOptions) -> Result<Self, Error> {
        if options.protocol.is_some() != options.protocolPath.is_some() { return Err(Error::MutuallyInclusive("options.protocol".to_string(), "options.protocolPath".to_string())); }
        if options.data.is_some() == options.dataCid.is_some() { return Err(Error::MutuallyExclusive("options.data".to_string(), "options.dataCid".to_string())); }
        if options.data.is_some() != options.dataSize.is_some() { return Err(Error::MutuallyInclusive("options.data".to_string(), "options.dataSize".to_string())); }
        if options.delegatedGrant.is_some() && options.signer.is_none() { return Err(Error::Dependant("options.delegatedGrant".to_string(), "options.signer".to_string())); }

        let dataCid = options.dataCid.unwrap_or(Cid::dagpb_cid(options.data.as_ref().unwrap()));
        let dataSize = options.dataSize.unwrap_or(options.data.as_ref().unwrap().len());

        let currentTime = Utc::now().to_rfc3339_opts(SecondsFormat::Micros, true);

        let descriptor = Descriptor{
            interface        : DwnInterfaceName::Records,
            method           : DwnMethodName::Write,
            messageTimestamp : options.messageTimestamp.unwrap_or(currentTime.clone()),

            protocol         : options.protocol,
            protocolPath     : options.protocolPath,
            recipient        : options.recipient,
            schema           : options.schema,
            tags             : options.tags,
            parentId         : Self::getRecordIdFromContextId(&options.parentContextId),
            dataCid          : Some(dataCid),
            dataSize         : Some(dataSize),
            dateCreated      : options.dateCreated.or(Some(currentTime.clone())),
            published        : options.published,
            datePublished    : options.datePublished.or(options.published.filter(|p| *p).map(|_| currentTime.clone())),
            dataFormat       : Some(options.dataFormat)
        };

        let recordId = options.recordId;
        let descriptorCid = Cid::dagcbor_cid(&serde_ipld_dagcbor::to_vec(&descriptor)?);
        let attestation = Self::createAttestation(descriptorCid, options.attestationSigners)?;
        let encryption = Self::createEncryptionProperty(&descriptor, options.encryptionInput)?;

        let message = RecordsWriteMessage{
            authorization: None,
            descriptor,
            recordId,
            contextId: None,
            attestation,
            encryption
        };

        let mut recordsWrite = RecordsWrite::new(message, options.parentContextId);

        if let Some(signer) = options.signer {
            recordsWrite.sign(
                signer,
                options.delegatedGrant,
                options.permissionGrantId,
                options.protocolRole
          );
        }

        Ok(recordsWrite)
    }

    pub fn getEntryId(author: &Did, descriptor: &Descriptor) -> Result<String, Error> {
        Ok(Cid::dagcbor_cid(&serde_ipld_dagcbor::to_vec(&EntryIdInput{descriptor: descriptor.clone(), author: author.clone()})?))
    }

    pub fn sign(
        &mut self,
        signer: Signer,
        delegatedGrant: Option<DelegatedGrant>,
        permissionGrantId: Option<String>,
        protocolRole: Option<String>
    ) -> Result<(), Error> {
        if self.message.authorization.is_some() || self.signaturePayload.is_some() || self.author.is_some() || self.message.contextId.is_some() {
            return Err(Error::InvalidArgument("Called .sign() on an instance of RecordsWrite that contains message.authorization||message.contextId||signaturePayload||author these properties will be overwritten".to_string()));
        }
        let (delegatedGrantId, author) = if let Some(delegatedGrant) = &delegatedGrant {
            (Some(Cid::dagcbor_cid(&serde_ipld_dagcbor::to_vec(delegatedGrant)?)),
            delegatedGrant.signature.get_signer())
        } else {
            (None, signer.key_uri().did())
        };

        let descriptor = &self.message.descriptor;
        let descriptorCid = Cid::dagcbor_cid(&serde_ipld_dagcbor::to_vec(&descriptor)?);

        let recordId = Some(self.message.recordId.clone().unwrap_or(Self::getEntryId(&author, &descriptor)?));

        let contextId = if self.message.descriptor.protocol.is_some() {
            if self.parentContextId.is_some() && !self.parentContextId.as_ref().unwrap().is_empty() {
                Some(format!("{}/{}", self.parentContextId.as_ref().unwrap(), recordId.as_ref().unwrap()))
            } else {
                recordId.clone()
            }
        } else { None };

        let attestationCid = match &self.message.attestation {
            Some(a) => Some(Cid::dagcbor_cid(&serde_ipld_dagcbor::to_vec(&a)?)),
            None => None
        };
        let encryptionCid = match &self.message.encryption {
            Some(e) => Some(Cid::dagcbor_cid(&serde_ipld_dagcbor::to_vec(&e)?)),
            None => None
        };

        let signaturePayload = SignaturePayload{
            descriptorCid,

            recordId  : recordId.clone(),
            contextId : contextId.clone(),
            protocolRole,
            encryptionCid,
            attestationCid,
            delegatedGrantId,
            permissionGrantId,
        };

        self.signaturePayload = Some(signaturePayload.clone());
        self.message.contextId = contextId;
        self.message.recordId = recordId;
        self.author = Some(author);
        self.message.authorization = Some(AuthorizationModel{
            signature: GeneralJws::create(signaturePayload, vec![signer])?,
            authorDelegatedGrant: delegatedGrant,
            ownerSignature: None,
            ownerDelegatedGrant: None
        });
        Ok(())
    }
}
