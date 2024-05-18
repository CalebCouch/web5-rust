use crate::crypto::jwk::JWK;

use super::did_core::{DidDocument, DidDocumentMetadata};

pub struct DidMetadata {
    did_document_metadata: DidDocumentMetadata,
    published: Option<bool>
}

pub struct PortableDid {
  uri: String,
  document: DidDocument,
  metadata: DidMetadata,
  private_keys: Option<Vec<JWK>>
}


