use super::did_core::{DidResolutionResult, DidDocument, DidVerificationMethod};

pub struct DidCreateVerificationMethod<T: CryptoApi> {
    algorithm: T,
    dvm: DidVerificationMethod,
    purposes: Option<Vec<DidVerificationRelationship>>
}

pub trait DidMethod {
    fn get_signing_method(did_document: DidDocument, method_id: Option<String>) -> impl std::future::Future<Output = Result<Option<DidVerificationMethod>, Error>> + Send;

    //Was options = Option<DidResolutionOptions> \/
    fn resolve(did_uri: String, accept: Option<String>) -> impl std::future::Future<Output = Result<Option<DidResolutionResult>, Error>> + Send;

}
