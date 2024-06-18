#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Could not parse type ({0}) from: {1}")]
    Parse(String, String),

    #[error(transparent)]
    TryFromSlice(#[from] std::array::TryFromSliceError),
    #[error(transparent)]
    Common(#[from] crate::common::error::Error),
    #[error(transparent)]
    Utf8(#[from] std::str::Utf8Error),
    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),
    #[error(transparent)]
    Ed25519(#[from] ed25519_dalek::ed25519::Error),
    #[error(transparent)]
    LibSecp256K1(#[from] libsecp256k1_core::Error),
    #[error(transparent)]
    JWTK(#[from] jwtk::Error),

    #[error("Downcast failed")]
    DowncastFailure(),
    #[error("{0}")]
    JoseB64(String),
    #[error("Thumbprint could not be calculated for PublicKey")]
    Thumbprint(),
    #[error("Invalid key provided. Must be an elliptic curve (EC) private key")]
    InvalidSecretKey(),
    #[error("The type of curve is not supported by the chosen algorithm: {0}")]
    UnsupportedCurve(String),
    #[error("Cannot access the cords of the identity point ofa curve")]
    IdentityPointCordAccess(),
    #[error("Jwk was not a private key")]
    NotSecretJwk(),

    #[error("{0} is not supported for {1}")]
    Unsupported(String, String),
}

impl From<jose_b64::base64ct::InvalidLengthError> for Error {
    fn from(value: jose_b64::base64ct::InvalidLengthError) -> Self {
        Error::JoseB64(value.to_string())
    }
}
