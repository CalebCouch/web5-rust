use super::error::Error;
use crate::dids::did_core::{DidUri, Url};
use crate::crypto::common::GenericPublicKey;

use quick_protobuf::message::MessageRead;

use std::time::{UNIX_EPOCH, SystemTime};
use std::collections::HashMap;

use unixfs_v1::file::adder::{Chunker, FileAdderBuilder};

use libipld::cid;

//use multibase::Base;
use cid::multihash::MultihashDigest;

use serde::{Serialize, Deserialize};

pub struct GeneralJws {
  payload: String,
  signatures: Vec<SignatureEntry>
}

pub struct SignatureEntry {
  protected: String,
  signature: String
}

//  export type RecordsWriteTagValue = string | number | boolean | string[] | number[];
//  export type RecordsWriteTags = {
//    [property: string]: RecordsWriteTagValue;
//  };
pub type RecordsWriteTags = HashMap<String, Vec<String>>;

pub struct Signer {
  keyUrl: DidUri,
  algorithm: String,
  sign: Box<dyn Fn(Vec<u8>) -> Vec<u8>>
}

pub enum KeyDerivationScheme {
  DataFormats, // = 'dataFormats',
  ProtocolContext, // = 'protocolContext',
  ProtocolPath, // = 'protocolPath',
  Schemas, // = 'schemas'
}

pub enum EncryptionAlgorithm {
  Aes256Ctr, // = 'A256CTR',
  EciesSecp256k1 // = 'ECIES-ES256K'
}

pub struct EncryptedKey {
  rootKeyUri: DidUri,
  derivedPublicKey: Option<GenericPublicKey>,
  derivationScheme: KeyDerivationScheme,
  algorithm: EncryptionAlgorithm,
  initializationVector: String,
  ephemeralPublicKey: GenericPublicKey,
  messageAuthenticationCode: String,
  encryptedKey: String
}

pub struct EncryptionProperty {
  algorithm: EncryptionAlgorithm,
  initializationVector: String,
  keyEncryption: Vec<EncryptedKey>
}

pub enum DwnInterfaceName {
  Events, // = 'Events',
  Messages, // = 'Messages',
  Protocols, // = 'Protocols',
  Records // = 'Records'
}

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
pub struct Authorization {
    signature: GeneralJws
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RecordsWriteDescriptor {
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocolPath: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recipient: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    schema: Option<Url>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parentId: Option<String>,
    dataCid: String,
    dataSize: usize,
    dateCreated: String,
    messageTimestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    published: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    datePublished: Option<String>,
    dataFormat: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<RecordsWriteTags>
}

impl RecordsWriteDescriptor {
    pub fn interface(&self) -> DwnInterfaceName { DwnInterfaceName::Records }
    pub fn method(&self) -> DwnMethodName { DwnMethodName::Write }
}

//DelegatedGrantRecordsWriteMessage.descriptor
pub struct DGRWMDescriptor {
    protocol: Option<String>,
    protocolPath: Option<String>,
    recipient: Option<String>,
    schema: Option<String>,
    parentId: Option<String>,
    dataCid: String,
    dataSize: u64,
    dateCreated: String,
    messageTimestamp: String,
    published: Option<bool>,
    datePublished: Option<String>,
    dataFormat: String,
}

impl DGRWMDescriptor {
    pub fn interface(&self) -> DwnInterfaceName { DwnInterfaceName::Records }
    pub fn method(&self) -> DwnMethodName { DwnMethodName::Write }
}

pub struct DelegatedGrantRecordsWriteMessage {
    authorization: Authorization,
    recordId: Option<String>,
    contextId: Option<String>,
    descriptor: DGRWMDescriptor
}

pub struct AuthorizationModel {
  signature: GeneralJws,
  authorDelegatedGrant: Option<DelegatedGrantRecordsWriteMessage>,
  ownerSignature: Option<GeneralJws>,
  ownerDelegatedGrant: Option<DelegatedGrantRecordsWriteMessage>
}


pub struct RecordsWriteMessage {
  authorization: AuthorizationModel,
  recordId: String,
  contextId: Option<String>,
  descriptor: RecordsWriteDescriptor,
  attestation: Option<GeneralJws>,
  encryption: Option<EncryptionProperty>
}

pub struct EncryptionInput {
  algorithm: Option<EncryptionAlgorithm>,
  initializationVector: Vec<u8>,
  key: Vec<u8>,
  keyEncryptionInputs: Vec<KeyEncryptionInput>
}

pub struct KeyEncryptionInput {
  derivationScheme: KeyDerivationScheme,
  publicKeyId: String,
  publicKey: GenericPublicKey,
  algorithm: Option<EncryptionAlgorithm>
}

pub struct RecordsWriteOptions {
    pub dataFormat: String,

    pub recipient: Option<String>,
    pub protocol: Option<Url>,
    pub protocolPath: Option<String>,
    pub protocolRole: Option<String>,
    pub schema: Option<Url>,
    pub tags: Option<RecordsWriteTags>,
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
    pub delegatedGrant: Option<RecordsWriteMessage>,
    pub attestationSigners: Option<Vec<Signer>>,
    pub encryptionInput: Option<EncryptionInput>,
    pub permissionGrantId: Option<String>
}

pub struct Descriptor {
  interface: String,
  method: String,
  messageTimestamp: String
}

pub struct GenericMessage {
  descriptor: Descriptor,
  authorization: Option<AuthorizationModel>
}

pub struct GenericSignaturePayload {
  descriptorCid: String,
  permissionGrantId: Option<String>,
  delegatedGrantId: Option<String>,
  protocolRole: Option<String>
}

pub trait MessageInterface {
  fn get_message() -> GenericMessage;
  fn get_signer() -> Option<String>;
  fn get_author() -> Option<String>;
  fn get_signaturePayload() -> Option<GenericSignaturePayload>;
}

pub struct Cid {}

impl Cid {

    pub fn cid_from_bytes(content: Vec<u8>) -> Result<String, Error> {
        Ok(cid::Cid::new_v1(0x55, cid::multihash::Code::Sha2_256.digest(&content)).to_string())
    }

    pub async fn dagpb_from_bytes(content: &[u8]) -> Result<String, Error> {
        let mut fileAdder = FileAdderBuilder::default()
            .with_chunker(Chunker::Size(256 * 1024))
            .build();
        fileAdder.push(content);
        let mut blocks: Vec<(libipld::cid::Cid, Vec<u8>)> = fileAdder.finish().collect();
        Ok(blocks.pop().map(|(c, d)| c.to_string()).unwrap_or("".to_string()))
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct RecordsWriteDescriptorS {
    method: String,
    interface: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocol: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    protocolPath: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recipient: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    schema: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    parentId: Option<String>,
    dataCid: String,
    dataSize: usize,
    dateCreated: String,
    messageTimestamp: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    published: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    datePublished: Option<String>,
    dataFormat: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    tags: Option<RecordsWriteTags>
}

pub struct RecordsWrite {

}

impl RecordsWrite {
    fn getRecordIdFromContextId(contextId: Option<String>) -> Option<String> {
        return contextId.map(|c| c.split('/').filter(|s| !s.is_empty()).collect::<Vec<&str>>().pop().map(|p| p.to_string())).flatten();
    }

    pub async fn create(options: RecordsWriteOptions) -> Result<Self, Error> {
        if options.protocol.is_some() != options.protocolPath.is_some() { return Err(Error::MutuallyInclusive("protocol".to_string(), "protocolPath".to_string())); }
        if options.data.is_some() == options.dataCid.is_some() { return Err(Error::MutuallyExclusive("data".to_string(), "dataCid".to_string())); }
        if options.data.is_some() != options.dataSize.is_some() { return Err(Error::MutuallyInclusive("data".to_string(), "dataSize".to_string())); }
        if options.delegatedGrant.is_some() != options.signer.is_some() { return Err(Error::Dependant("delegatedGrant".to_string(), "signer".to_string())); }

        let dataCid = options.dataCid.unwrap_or(Cid::dagpb_from_bytes(options.data.as_ref().unwrap()).await?);
        println!("dataCid: {:?}", dataCid);
        let dataSize = options.dataSize.unwrap_or(options.data.as_ref().unwrap().len());

        let currentTime = SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros().to_string();

        let descriptor = RecordsWriteDescriptorS{
          interface        : "Records".to_string(),
          method           : "Write".to_string(),
          protocol         : options.protocol.map(|u| u.to_string()),
          protocolPath     : options.protocolPath,
          recipient        : options.recipient,
          schema           : options.schema.map(|u| u.to_string()),
          tags             : options.tags,
          parentId         : Self::getRecordIdFromContextId(options.parentContextId),
          dataCid,
          dataSize,
          dateCreated      : "2024-06-12T19:12:37.719551Z".to_string(), //options.dateCreated.unwrap_or(currentTime.clone()), TODO make sure formats correctly
          messageTimestamp : "2024-06-12T19:12:39.987557Z".to_string(), //options.messageTimestamp.unwrap_or(currentTime.clone()),
          published        : options.published,
          datePublished    : options.datePublished.or(options.published.filter(|p| *p).map(|_| currentTime.clone())),
          dataFormat       : options.dataFormat
        };
        println!("desc: {:?}", descriptor);
        println!("desc: {:?}", serde_ipld_dagcbor::to_vec(&descriptor).unwrap());
        println!("descSize: {:?}", serde_ipld_dagcbor::to_vec(&descriptor).unwrap().len());

        let recordId = options.recordId;

        //let descriptorCid = await Cid.computeCid(descriptor);
        //println!("desCid: {:?}", descriptorCid);


        Ok(RecordsWrite{})
    }
}
