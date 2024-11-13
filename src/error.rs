use snafu::Snafu;

fn get_backtrace() -> snafu::Backtrace {
    snafu::Backtrace::capture()
}

#[derive(Debug, Snafu)]
#[snafu(module)]
pub enum Error {
    #[snafu(transparent)]
    Hex{source: hex::FromHexError, backtrace: snafu::Backtrace},
    #[snafu(transparent)]
    Ed25519{source: ed25519_dalek::ed25519::Error, backtrace: snafu::Backtrace},
    #[snafu(transparent)]
    Base64Decode{source: base64::DecodeError, backtrace: snafu::Backtrace},
    #[snafu(transparent)]
    TryFromSlice{source: std::array::TryFromSliceError, backtrace: snafu::Backtrace},
    #[snafu(transparent)]
    Zbase32{source: zbase32::DecodeError},
    #[snafu(transparent)]
    SimpleCrypto{source: simple_crypto::Error, backtrace: snafu::Backtrace},
    #[snafu(transparent)]
    FromStringUtf8{source: std::string::FromUtf8Error, backtrace: snafu::Backtrace},
    #[snafu(transparent)]
    SimpleDns{source: simple_dns::SimpleDnsError, backtrace: snafu::Backtrace},
    #[snafu(transparent)]
    UrlParse{source: url::ParseError, backtrace: snafu::Backtrace},
    #[snafu(transparent)]
    SerdeJson{source: serde_json::Error, backtrace: snafu::Backtrace},
    #[snafu(transparent)]
    SimpleDatabase{source: simple_database::Error, backtrace: snafu::Backtrace},
    #[snafu(transparent)]
    Regex{source: regex::Error, backtrace: snafu::Backtrace},
    #[snafu(transparent)]
    Reqwest{source: reqwest::Error, backtrace: snafu::Backtrace},
    #[snafu(transparent)]
    SystemTime{source: std::time::SystemTimeError, backtrace: snafu::Backtrace},
    #[snafu(transparent)]
    SerdeBencode{source: serde_bencode::Error, backtrace: snafu::Backtrace},
    #[snafu(transparent)]
    Io{source: std::io::Error, backtrace: snafu::Backtrace},
    #[snafu(transparent)]
    Arc{source: std::sync::Arc<Error>},

    #[snafu(display("{message}"))]
    FailedDowncast{
        message: String,
        backtrace: snafu::Backtrace
    },
    #[snafu(display("Validation Error: {message}"))]
    Validation{message: String, backtrace: snafu::Backtrace},

    #[snafu(display("Could not parse type ({message}) from: {message1}"))]
    Parse{message: String, message1: String, backtrace: snafu::Backtrace},
    #[snafu(display("Invalid Authentication: ({message})"))]
    InvalidAuth{message: String, backtrace: snafu::Backtrace},
    #[snafu(display("Bad Response: {message}"))]
    BadResponse{message: String, backtrace: snafu::Backtrace},
    #[snafu(display("Bad Request: {message}"))]
    BadRequest{message: String, backtrace: snafu::Backtrace},
    #[snafu(display("Could Not Find: {message}"))]
    NotFound{message: String, backtrace: snafu::Backtrace},
    #[snafu(display("JsonRpc: {message}"))]
    JsonRpc{message: String, backtrace: snafu::Backtrace},

    #[snafu(display("Multi: {errors:?}"))]
    Multi{errors: Vec<Error>},

    #[snafu(display("InsufficentPermission"))]
    InsufficentPermission{backtrace: snafu::Backtrace},

    #[snafu(whatever)]
    Custom{message: String}
}

impl Error {
    pub fn custom(message: &str) -> Self {
        Error::Custom{message: message.to_string()}
    }

    pub fn bad_request(msg: &str) -> Self {
        Error::BadRequest{message: msg.to_string(), backtrace: get_backtrace()}
    }
    pub fn bad_response(msg: &str) -> Self {
        Error::BadResponse{message: msg.to_string(), backtrace: get_backtrace()}
    }
    pub fn invalid_auth(msg: &str) -> Self {
        Error::InvalidAuth{message: msg.to_string(), backtrace: get_backtrace()}
    }
    pub fn not_found(msg: &str) -> Self {
        Error::NotFound{message: msg.to_string(), backtrace: get_backtrace()}
    }
    pub fn json_rpc(msg: &str) -> Self {
        Error::JsonRpc{message: msg.to_string(), backtrace: get_backtrace()}
    }
    pub fn validation(msg: &str) -> Self {
        Error::Validation{message: msg.to_string(), backtrace: get_backtrace()}
    }

    pub fn multi(errors: Vec<Box<crate::agent::structs::ErrorWrapper>>) -> Self {
        errors.into()
    }

    pub fn insufficent_permission() -> Self {
        Error::InsufficentPermission{backtrace: get_backtrace()}
    }

    pub fn parse(r#type: &str, data: &str) -> Self {
        Error::Parse{message: r#type.to_string(), message1: data.to_string(), backtrace: get_backtrace()}
    }

    pub fn arc(err: std::sync::Arc<Error>) -> Self {
        Error::Arc{source: err}
    }
}

impl From<Vec<Box<crate::agent::structs::ErrorWrapper>>> for Error {
    fn from(mut errors: Vec<Box<crate::agent::structs::ErrorWrapper>>) -> Error {
        if errors.len() > 1 {
            Error::Multi{errors: errors.into_iter().map(|err| Error::arc((err).inner)).collect::<Vec<_>>()}
        } else {
            Error::arc((errors.remove(0)).inner)
        }
    }
}

impl From<Box<dyn crate::agent::traits::Response>> for Error {
    fn from(r: Box<dyn crate::agent::traits::Response>) -> Error {
        Error::FailedDowncast{
            message: format!("Tried to downcast {:?}: {} into something else", r, (*r).get_full_type()),
            backtrace: get_backtrace()
        }
    }
}
