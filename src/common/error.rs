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
    #[error("{0}")]
    LevelDB(String),
    #[error("Either 'name' or 'code' must be defined, but not both")]
    NameOrCode(),
    #[error("Unsupported Multicodec: {0}")]
    UnsupportedMulticodec(String),
    #[error(transparent)]
    IO(#[from] std::io::Error),
    #[error(transparent)]
    Zbase32(#[from] zbase32::DecodeError),
}

impl From<leveldb_rs::LevelDBError> for Error {
    fn from(value: leveldb_rs::LevelDBError) -> Self {
        Error::LevelDB(value.to_string())
    }
}
