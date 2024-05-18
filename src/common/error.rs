#[derive(thiserror::Error, Debug)]
pub enum Error {
//  #[error(transparent)]
//  LevelDB(#[from] leveldb_rs::LevelDBError),
//  #[error("{}", .0)]
//  LevelDB(leveldb_rs::LevelDBError),

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
}

impl From<leveldb_rs::LevelDBError> for Error {
    fn from(value: leveldb_rs::LevelDBError) -> Self {
        Error::LevelDB(value.to_string())
    }
}
