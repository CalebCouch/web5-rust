//import { varint } from 'multiformats';
use varint_rs::{VarintWriter, VarintReader};
use super::error::Error;

use std::collections::HashMap;
use std::io::{Cursor, Write};

type MulticodecCode = i32;

pub struct MulticodecDefinition  {
  code: MulticodecCode,
  name: String
}

#[derive(Default)]
pub struct Multicodec {
  code_to_name: HashMap<MulticodecCode, String>,
  name_to_code: HashMap<String, MulticodecCode>
}

impl Multicodec {
    pub fn new() -> Multicodec {
        let mut multi = Multicodec::default();
        multi.register_codec(MulticodecDefinition{code: 0xed, name: "ed25519-pub".to_owned()});
        multi.register_codec(MulticodecDefinition{code: 0x1300, name: "ed25519-priv".to_owned()});
        multi.register_codec(MulticodecDefinition{code: 0xec, name: "x25519-pub".to_owned()});
        multi.register_codec(MulticodecDefinition{code: 0x1302, name: "x25519-priv".to_owned()});
        multi.register_codec(MulticodecDefinition{code: 0xe7, name: "secp256k1-pub".to_owned()});
        multi.register_codec(MulticodecDefinition{code: 0x1301, name: "secp256k1-priv".to_owned()});
        multi
    }

    pub fn add_prefix(&self, code: Option<MulticodecCode>, name: Option<String>, data: Vec<u8>) -> Result<Vec<u8>, Error> {
        if name.is_some() && code.is_some() { return Err(Error::NameOrCode()); }
        let code = if let Some(code) = code {
            if self.code_to_name.contains_key(&code) {
                code
            } else { return Err(Error::UnsupportedMulticodec(code.to_string())); }
        } else if let Some(name) = name {
            if let Some(code) = self.name_to_code.get(&name) {
                *code
            } else { return Err(Error::UnsupportedMulticodec(name)); }
        } else { return Err(Error::NameOrCode())? };

        let mut data_with_prefix: Cursor<Vec<u8>> = Cursor::new(Vec::new());
        data_with_prefix.write_i32_varint(code)?;
        data_with_prefix.write_all(&data)?;
        Ok(data_with_prefix.into_inner())
    }

    pub fn get_code_from_data(data: Vec<u8>) -> Result<MulticodecCode, Error> {
        let mut data_with_prefix = Cursor::new(data);
        Ok(data_with_prefix.read_i32_varint()?)
    }

    pub fn get_code_from_name(&self, name: String) -> Result<MulticodecCode, Error> {
        if let Some(code) = self.name_to_code.get(&name) {
            return Ok(*code);
        }
        Err(Error::UnsupportedMulticodec(name))
    }

    pub fn get_name_from_code(&self, code: MulticodecCode) -> Result<String, Error> {
        if let Some(name) = self.code_to_name.get(&code) {
            return Ok(name.to_string());
        }
        Err(Error::UnsupportedMulticodec(code.to_string()))
    }

    pub fn register_codec(&mut self, codec: MulticodecDefinition) {
        self.code_to_name.insert(codec.code, codec.name.clone());
        self.name_to_code.insert(codec.name, codec.code);
    }

    pub fn remove_prefix(&self, data: Vec<u8>) -> Result<(MulticodecCode, Vec<u8>, String), Error> {
        let mut data_with_prefix = Cursor::new(data);
        let code = data_with_prefix.read_i32_varint()?;
        if let Some(name) = self.code_to_name.get(&code) {
            Ok((code, data_with_prefix.into_inner(), name.to_string()))
        } else {
            Err(Error::UnsupportedMulticodec(code.to_string()))
        }
    }
}

//  // Pre-defined registered codecs:

