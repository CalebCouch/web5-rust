#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Common(#[from] crate::common::error::Error),
    #[error(transparent)]
    Crypto(#[from] crate::crypto::error::Error),
    #[error(transparent)]
    Dids(#[from] crate::dids::error::Error),
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
    #[error(transparent)]
    QuickProtobuf(#[from] quick_protobuf::Error),
    #[error(transparent)]
    RustIpfs(#[from] rust_ipfs::Error),
    #[error(transparent)]
    Cid(#[from] cid::Error),
    #[error(transparent)]
    Multihash(#[from] multihash::Error),
    #[error(transparent)]
    IpldCid(#[from] libipld::cid::Error),
    #[error(transparent)]
    SerdeCbor(#[from] serde_ipld_dagcbor::EncodeError<std::collections::TryReserveError>),


    #[error("if {0} is present so must {1} be, they are mutually inclusive")]
    MutuallyInclusive(String, String),
    #[error("if {0} is present then {1} must not be, they are mutually exclusive")]
    MutuallyExclusive(String, String),
    #[error("{0} depends on {1} and it must be present")]
    Dependant(String, String),
    #[error("{0}")]
    InvalidArgument(String),
    #[error("{0} requires that {1} and it was not")]
    Requires(String, String),
    #[error("{0} is not supported for {1}")]
    Unsupported(String, String),
}
