use crate::error::Error;
use crate::test_utils::MemoryDidResolver;

#[tokio::test]
async fn did_round_trip() {
    let result: Result<(), Error> = async {
        let secret_key = ed25519::SecretKey::generate_key();
        let identity_key = DidKey::new(
            Some("0".to_string()),
            secret_key.public_key(),
            vec![DidKeyPurpose::Auth, DidKeyPurpose::Asm, DidKeyPurpose::Inv, DidKeyPurpose::Del],
            None
        )?;

        let secret_key = ed25519::SecretKey::generate_key();
        let signing_key = DidKey::new(
            Some("sig".to_string()),
            secret_key.public_key(),
            vec![DidKeyPurpose::Auth, DidKeyPurpose::Asm],
            None
        )?;

        let ext_key = ExtendedSecretKey::generate_key();
        let encryption_key = DidKey::new(
            Some("enc".to_string()),
            ext_key.key().public_key(),
            vec![DidKeyPurpose::Agm],
            None
        )?;

        let mut keys = BTreeMap::default();
        keys.insert("0".to_string(), identity_key);
        keys.insert("sig".to_string(), signing_key);
        keys.insert("enc".to_string(), encryption_key);

        let mut services = BTreeMap::default();
        services.insert("dwn".to_string(), DidService{
            id: "dwn".to_string(),
            types: vec!["DecentralizedWebNode".to_string()],
            service_endpoints,
            enc: vec!["enc".to_string()],
            sig: vec!["sig".to_string()]
        });

        let doc = DhtDocument::new(Vec::new(), Vec::new(), services, keys, Vec::new())?;

        Ok(())
    }.await;
    assert!(result.is_ok())
}
