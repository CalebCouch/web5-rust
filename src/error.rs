#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Hex(#[from] hex::FromHexError),
    #[error(transparent)]
    Reqwest(#[from] reqwest::Error),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    SerdeBencode(#[from] serde_bencode::Error),
    #[error(transparent)]
    SystemTime(#[from] std::time::SystemTimeError),
    #[error(transparent)]
    SimpleDns(#[from] simple_dns::SimpleDnsError),
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
    #[error(transparent)]
    ErasedSerde(#[from] erased_serde::Error),
    #[error(transparent)]
    UrlParse(#[from] url::ParseError),
    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),
    #[error(transparent)]
    FromStringUtf8(#[from] std::string::FromUtf8Error),
    #[error(transparent)]
    FromStrUtf8(#[from] std::str::Utf8Error),
    #[error(transparent)]
    Ed25519(#[from] ed25519_dalek::ed25519::Error),
    #[error(transparent)]
    Base64Decode(#[from] base64::DecodeError),
    #[error(transparent)]
    Zbase32(#[from] zbase32::DecodeError),
    #[error(transparent)]
    Regex(#[from] regex::Error),
    #[error(transparent)]
    ChronoParse(#[from] chrono::ParseError),
    #[error(transparent)]
    RusqliteDB(#[from] rusqlite::Error),
    #[error(transparent)]
    JoinError(#[from] tokio::task::JoinError),
    #[error(transparent)]
    Secp256k1(#[from] secp256k1::Error),
    #[error(transparent)]
    BitcoinBip32(#[from] bitcoin::bip32::Error),
    #[error(transparent)]
    HashFromSlice(#[from] bitcoin_hashes::FromSliceError),

    #[error("{0}")]
    JsonValidation(String),
    #[error("{0}")]
    JsonRpc(String),
//  #[error(transparent)]
//  JsonRpcHttp(#[from] jsonrpc::simple_http::Error),
//  #[error(transparent)]
//  JsonRpc(#[from] jsonrpc::Error),

    #[cfg(feature = "leveldb")]
    #[error(transparent)]
    LevelDB(#[from] leveldb::error::Error),
    #[error("Exited, Reason: {0}")]
    Exited(String),


    #[error("Could not parse type ({0}) from: {1}")]
    Parse(String, String),
    #[error("Bad Request: {0}: {1}")]
    BadRequest(String, String), //400
    #[error("Auth failed {0}: {1}")]
    AuthFailed(String, String), //401
    #[error("Not Found {0}: {1}")]
    NotFound(String, String), //404
    #[error("Conflict {0}: {1}")]
    Conflict(String, String), //409
    #[error("Error {0}: {1}")]
    Error(String, String), //500
}

impl Error {
    pub fn bad_request(ctx: &str, err: &str) -> Self {
        Error::BadRequest(ctx.to_string(), err.to_string())
    }
    pub fn auth_failed(ctx: &str, err: &str) -> Self {
        Error::AuthFailed(ctx.to_string(), err.to_string())
    }
    pub fn not_found(ctx: &str, err: &str) -> Self {
        Error::NotFound(ctx.to_string(), err.to_string())
    }
    pub fn conflict(ctx: &str, err: &str) -> Self {
        Error::Conflict(ctx.to_string(), err.to_string())
    }
    pub fn parse(r#type: &str, data: &str) -> Self {Error::Parse(r#type.to_string(), data.to_string())}
    pub fn err(ctx: &str, err: &str) -> Self {Error::Error(ctx.to_string(), err.to_string())}
}

