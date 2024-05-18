//use super::error::Error;

use crate::crypto::jwk::JWK;
use std::collections::HashMap;

pub struct DidDereferencingMetadata  {
  content_type: Option<String>,
  error: Option<String>,

  //TODO
  //[key: string]: any;
}

pub struct DidDereferencingOptions {
    accept: Option<String>,
    //TODO
    //[key: string]: any;
}

pub struct DidDereferencingResult {
    dereferencing_metadata: DidDereferencingMetadata,
    content_stream: Option<DidResource>,
    content_metadata: DidDocumentMetadata,
}

pub struct DidDocument {
    //TODO
    //'@context'?: 'https://www.w3.org/ns/did/v1' | string | (string | Record<string, any>)[];
    id: String,
    also_known_as: Option<Vec<String>>,
    controller: Option<Vec<String>>,
    verification_method: Option<Vec<DidVerificationMethod>>,
    assertion_method: Option<Vec<DidVerificationMethod>>,
    //Was DidVerificationMethod|string ^^^^
    authentication: Option<Vec<DidVerificationMethod>>,
    //Was DidVerificationMethod|string ^^^^
    key_agreement: Option<Vec<DidVerificationMethod>>,
    //Was DidVerificationMethod|string ^^^^
    capability_delegation: Option<Vec<DidVerificationMethod>>,
    //Was DidVerificationMethod|string ^^^^
    capability_invocation: Option<Vec<DidVerificationMethod>>,
    //Was DidVerificationMethod|string ^^^^
    service: Option<Vec<DidService>>,
}


pub struct DidDocumentMetadata {
  created: Option<String>,
  updated: Option<String>,
  deactivated: Option<bool>,
  version_id: Option<String>,
  next_update: Option<String>,
  next_version_id: Option<String>,
  equivalent_id: Option<Vec<String>>,
  canonical_id: Option<String>,
  //TODO
  //[key: string]: any;
}

pub struct DidResolutionMetadata {
    content_type: Option<String>,
    error: Option<String>,
    //TODO
    //[key: string]: any;
}

pub struct DidResolutionOptions {
    accept: Option<String>,
    //TODO
    //[key: string]: any;
}
pub struct DidResolutionResult {
    //TODO
    //'@context'?: 'https://w3id.org/did-resolution/v1' | string | (string | Record<string, any>)[];
    did_resolution_metadata: DidResolutionMetadata,
    //TODO
    did_document: Option<DidDocument>,
    did_document_metadata: Option<DidDocumentMetadata>
}

pub enum DidResource {
    DidDocument(DidDocument),
    DidService(DidService),
    DidVerificationMethod(DidVerificationMethod)
}

pub struct DidService {
    id: String,
    r#type: String,
    service_endpoint: Vec<DidServiceEndpoint>,
    //TODO
    //[key: string]: any;
}

pub enum DidServiceEndpoint {
    Endpoint(String),
    Endpoints(HashMap<String, String>)
                            //^^^^^^ Was "any" in typescript
}

pub struct DidVerificationMethod {
    id: String,
    r#type: String,
    controller: String,
    public_key_jwk: Option<JWK>,
    public_key_multibase: Option<String>
}

pub enum DidVerificationRelationship {
    Authentication,
    AssertionMethod,
    KeyAgreement,
    CapabilityInvocation,
    CapabilityDelegation
}
