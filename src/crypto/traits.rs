pub use bitcoin_hashes::Hash as BHash;

use super::structs::Hash;

pub trait Hashable: erased_serde::Serialize {
    fn hash(&self) -> Hash {
        let mut ser = std::io::BufWriter::new(Vec::<u8>::new());
        let serializer = &mut serde_json::ser::Serializer::new(&mut ser);
        self.erased_serialize(&mut Box::new(<dyn erased_serde::Serializer>::erase(
            serializer
        ))).unwrap();
        Hash::new(<bitcoin_hashes::sha256::Hash as bitcoin_hashes::Hash>::hash(ser.buffer()))
    }
    fn hash_bytes(&self) -> Vec<u8> {self.hash().to_vec()}
}

impl Hashable for &[u8] {
    fn hash(&self) -> Hash {
        Hash::new(<bitcoin_hashes::sha256::Hash as bitcoin_hashes::Hash>::hash(self))
    }
}

impl Hashable for Vec<u8> {
    fn hash(&self) -> Hash {
        Hash::new(<bitcoin_hashes::sha256::Hash as bitcoin_hashes::Hash>::hash(self))
    }
}
