use super::Error;

use base64::prelude::{Engine as _, BASE64_URL_SAFE_NO_PAD};
use schemars::schema::{Schema, SchemaObject, StringValidation};

pub struct Schemas {}
impl Schemas {
    pub fn regex(regex: String) -> Schema {
        Schema::Object(SchemaObject{
            string: Some(Box::new(StringValidation {
                max_length: None,
                min_length: None,
                pattern: Some(regex)
            })),
            ..Default::default()
        })
    }
    pub fn any() -> Schema {
        Schema::Bool(true)
    }
}

pub enum Convert {
    ZBase32,
    Base64UrlUnpadded
}

impl Convert {
    pub fn encode(&self, data: &[u8]) -> String {
        match &self {
            Convert::ZBase32 => zbase32::encode(data),
            Convert::Base64UrlUnpadded => BASE64_URL_SAFE_NO_PAD.encode(data)
        }
    }

    pub fn decode(&self, input: &str) -> Result<Vec<u8>, Error> {
        Ok(match &self {
            Convert::ZBase32 => zbase32::decode(input)?,
            Convert::Base64UrlUnpadded => BASE64_URL_SAFE_NO_PAD.decode(input)?
        })
    }
}

