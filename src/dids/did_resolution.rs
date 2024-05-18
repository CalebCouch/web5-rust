//use crate::common::types::KeyValueStore;
use super::did_core::{DidDereferencingOptions, DidDereferencingResult, DidResolutionOptions, DidResolutionResult};

pub trait DidResolver {
    fn resolve(did_url: String, options: Option<DidResolutionOptions>) -> impl std::future::Future<Output = DidResolutionResult> + Send;
}

//TODO Where every DidResolverCache is extended as a trait skip and just implement A KVS
//export interface DidResolverCache extends KeyValueStore<string, DidResolutionResult | void> {}

pub trait DidUrlDereferencer {
    fn dereference(did_url: String, options: Option<DidDereferencingOptions>) -> impl std::future::Future<Output = DidDereferencingResult> + Send;
}

//TODO
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
