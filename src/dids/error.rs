#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Common(#[from] crate::common::error::Error),
    #[error(transparent)]
    Crypto(#[from] crate::crypto::error::Error),
    #[error(transparent)]
    FromUtf8(#[from] std::string::FromUtf8Error),
    #[error(transparent)]
    Bs58(#[from] bs58::decode::Error),
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    SerdeBencode(#[from] serde_bencode::Error),
    #[error(transparent)]
    SystemTime(#[from] std::time::SystemTimeError),
    #[error(transparent)]
    Regex(#[from] regex::Error),
    #[error(transparent)]
    SimpleDns(#[from] simple_dns::SimpleDnsError),
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
    #[error(transparent)]
    UrlParse(#[from] url::ParseError),
    #[error("Could not find secret key in key store")]
    KeyNotFound(),
    #[error("Could not parse did uri")]
    ParseDidUri(),
    #[error("Identity Key must have an Id of 0")]
    InvalidIdKeyId(),
    #[error("Ids were not unique")]
    NonUniqueIds(),
    #[error("{0}")]
    PkarrResponse(String),
    #[error("The did type ({0}) is not supported by the did method ({1})")]
    UnsupportedDidType(String, String),
    #[error("Could not parse type ({0}) from: {1}")]
    Parse(String, String),
    #[error("Service uri had no fragment")]
    NoServiceFragment(),
    #[error("Property cannot be inserted to Custom Properties because this property exists")]
    ExistingProperty(),
    #[error("DNS packet exceeds the 1000 byte maximum size: {0} bytes")]
    InvalidDidDocumentLength(String),




    #[error("The DID id supplied could not be parsed: {0}")]
    InvalidDidId(String),
    #[error("The DID URI supplied could not be parsed: {0}")]
    InvalidDidUri(String),
    #[error("The DID URI supplied does not conform to valid syntax: {0}")]
    InvalidDid(String),
    #[error("The DID Method supplied is not supported by the chosen DID resolver/parser: {0}")]
    InvalidDidMethod(String),
    #[error("An unexpected error occurred during the requested DID operation")]
    InternalError(),
    #[error("The DID document supplied does not conform to valid syntax")]
    InvalidDidDocument(),
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
    UnsupportedPublicKeyType(),
    #[error("At least one verification method is required for a DID")]
    VerificationMethodNotFound(),
    #[error("One or more verification method IDs are not unique")]
    NonUniqueId(),
}
