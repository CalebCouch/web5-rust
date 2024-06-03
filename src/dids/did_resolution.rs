//use crate::common::types::KeyValueStore;
use super::did_core::{DidDereferencingOptions, DidDereferencingResult, DidResolutionOptions, DidResolutionResult};

pub trait DidResolver {
    fn resolve(&self, did_url: String, options: Option<DidResolutionOptions>) -> impl std::future::Future<Output = DidResolutionResult> + Send;
}

//TODO trait alias are not yet available
//pub trait DidResolverCache = KeyValueStore<String, DidResolutionResult>;

pub trait DidUrlDereferencer {
    fn dereference(&self, did_url: String, options: Option<DidDereferencingOptions>) -> impl std::future::Future<Output = DidDereferencingResult> + Send;
}

//ODO
//  /**
//   * A constant representing an empty DID Resolution Result. This object is used as the basis for a
//   * result of DID resolution and is typically augmented with additional properties by the
//   * DID method resolver.
//   */

//  export const EMPTY_DID_RESOLUTION_RESULT: DidResolutionResult = {
//    '@context'            : 'https://w3id.org/did-resolution/v1',
//    didResolutionMetadata : {},
//    didDocument           : null,
//    didDocumentMetadata   : {},
//  }
