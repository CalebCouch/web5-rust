#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Could not convert from storage bytes to type")]
    FromStorageBytes(),
    #[error("Could not convert from type to storage bytes")]
    AsStorageBytes(),
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),
    #[error(transparent)]
    FromUtf8(#[from] std::string::FromUtf8Error),
    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
    #[error(transparent)]
    SystemTime(#[from] std::time::SystemTimeError),
    #[error(transparent)]
    Base64Decode(#[from] base64::DecodeError),
    #[error("Could not create or open DataStore")]
    DataStore(),
    #[error("Either 'name' or 'code' must be defined, but not both")]
    NameOrCode(),
    #[error("Unsupported Multicodec: {0}")]
    UnsupportedMulticodec(String),
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[error(transparent)]
    Zbase32(#[from] zbase32::DecodeError),
    #[error(transparent)]
    Regex(#[from] regex::Error),
    #[error(transparent)]
    IpldCid(#[from] libipld::cid::Error),
    #[error(transparent)]
    SerdeCborEncode(#[from] serde_ipld_dagcbor::EncodeError<std::collections::TryReserveError>),
    #[error(transparent)]
    SerdeCborDecode(#[from] serde_ipld_dagcbor::DecodeError<std::convert::Infallible>),
    #[error(transparent)]
    ChronoParse(#[from] chrono::ParseError),
    #[error(transparent)]
    UrlParse(#[from] url::ParseError),
    #[error(transparent)]
    LevelDB(#[from] leveldb::error::Error),



    #[error("if {0} is present or not so must {1} be, they are mutually inclusive")]
    MutuallyInclusive(String, String),
    #[error("if {0} is present then {1} must not be and vice versa, they are mutually exclusive")]
    MutuallyExclusive(String, String),
    #[error("{0} depends on {1} and it must be present")]
    Dependant(String, String),
    #[error("{0}")]
    InvalidArgument(String),
    #[error("{0} requires that {1} and it was not")]
    Requires(String, String),
    #[error("{0} is not supported for {1}")]
    Unsupported(String, String),
    #[error("Unable to find: {0}")]
    NotFound(String),
    #[error("Could not parse type ({0}) from: {1}")]
    Parse(String, String),
    #[error("Unexpected Error: {0}")]
    Unexpected(String),
}

//  impl From<leveldb_rs::LevelDBError> for Error {
//      fn from(value: leveldb_rs::LevelDBError) -> Self {
//          Error::LevelDB(value.to_string())
//      }
//  }
