use crate::crypto::secp256k1::SecretKey;

#[tokio::test]
async fn signature_roundtrip() {
    let secret_key = SecretKey::new();
    let data = b"a bunch of random test data".to_vec();
    let sig = secret_key.sign(&data);
    assert!(secret_key.public_key().verify(&data, &sig).is_ok())
}

#[tokio::test]
async fn ecies_roundtrip() {
    let secret_key = SecretKey::new();
    let public_key = secret_key.public_key();
    let data = b"a bunch of random test data".to_vec();
    let enc_data = public_key.encrypt(&data).unwrap();
    assert!(secret_key.decrypt(&enc_data).unwrap() == data)
}
