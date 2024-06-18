#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Common(#[from] crate::common::error::Error),
    #[error(transparent)]
    Crypto(#[from] crate::crypto::error::Error),
    #[error(transparent)]
    Dids(#[from] crate::dids::error::Error),
    #[error(transparent)]
    Dwn(#[from] crate::dwn::error::Error),
}
