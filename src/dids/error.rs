#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Regex(#[from] regex::Error),
    #[error("Could not parse did query params")]
    QueryParsing(),
    #[error("The DID supplied does not conform to valid syntax")]
    InvalidDid(),
    #[error("The supplied method name is not supported by the DID method and/or DID resolver implementation")]
    MethodNotSupported(),
    #[error("An unexpected error occurred during the requested DID operation")]
    InternalError(),
    #[error("The DID document supplied does not conform to valid syntax")]
    InvalidDidDocument(),
    #[error("The byte length of a DID document does not match the expected value")]
    InvalidDidDocumentLength(),
    #[error("The DID URL supplied to the dereferencing function does not conform to valid syntax")]
    InvalidDidUrl(),
    #[error("An invalid public key is detected during a DID operation")]
    InvalidPublicKey(),
    #[error("The byte length of a public key does not match the expected value")]
    InvalidPublicKeyLength(),
    #[error("An invalid public key type was detected during a DID operation")]
    InvalidPublicKeyType(),
    #[error("Verification of a signature failed during a DID operation")]
    InvalidSignature(),
    #[error("The DID resolver was unable to find the DID document resulting from the resolution request")]
    NotFound(),
    #[error("The representation requested via the `accept` input metadata property is not supported by the DID method and/or DID resolver implementation")]
    RepresentationNotSupported(),
    #[error("The type of a public key is not supported by the DID method and/or DID resolver implementation")]
    UnsupportedPublicKeyType()
}
