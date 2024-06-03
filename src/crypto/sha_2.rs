use crypto::sha2::Sha256 as BaseSha256;
use crypto::digest::Digest;

//Only supported Algo for Sha2 is Sha256
pub struct Sha2Algorithm {}

impl Sha2Algorithm {
    pub fn digest(data: Vec<u8>) -> Vec<u8> {
        let mut sha256 = BaseSha256::new();
        sha256.input(&data);
        let mut result: Vec<u8> = Vec::new();
        sha256.result(&mut result);
        result
    }
}


