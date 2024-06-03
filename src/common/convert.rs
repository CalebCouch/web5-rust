use super::Error;

use base64::prelude::{Engine as _, BASE64_URL_SAFE_NO_PAD, BASE64_URL_SAFE};

pub enum Convert {
    ZBase32,
    Base64Url,
    Base64UrlUnpadded
}

impl Convert {
    pub fn encode(&self, data: &[u8]) -> String {
        match &self {
            Convert::ZBase32 => zbase32::encode(data),
            Convert::Base64Url => BASE64_URL_SAFE.encode(data),
            Convert::Base64UrlUnpadded => BASE64_URL_SAFE_NO_PAD.encode(data)
        }
    }

    pub fn decode(&self, input: &str) -> Result<Vec<u8>, Error> {
        Ok(match &self {
            Convert::ZBase32 => zbase32::decode(input)?,
            Convert::Base64Url => BASE64_URL_SAFE.decode(input)?,
            Convert::Base64UrlUnpadded => BASE64_URL_SAFE_NO_PAD.decode(input)?
        })
    }
}

