
pub struct DirectMessageHandler {
    pub tenant: DidKeyPair,
    pub com_key: SecretKey,
    pub did_resolver: Box<dyn DidResolver>,
}

impl DirectMessageHandler {
    pub fn new(
        tenant: DidKeyPair,
        com_key: SecretKey,
        did_resolver: Box<dyn DidResolver>,
    ) -> Self {
        DirectMessageHandler{
            tenant,
            com_key,
            did_resolver,
        }
    }

    pub async fn establish_direct_messages(&mut self, recipient: &Did) -> Result<PermissionedRecord, Error> {
        let ldc_id = serde_json::to_vec("LAST_DM_CHECK")?.hash();
        let ldc_perms = PermissionSet::from_key(Path::new(Protocol::date_time().hash(), vec![]), &self.com_key)?;
        let last_dm_check = self.read(&ldc_perms, &[&self.tenant()]).await?.map(|record|
            serde_json::from_slice::<DateTime>(&record.1.payload)
        ).transpose()?.unwrap_or_default();

        //TODO: if last dm check was in the last 5-10 minutes return ok

        for (sender, permission) in self.client.read_did_msgs(&self.did_resolver, &self.tenant, &self.com_key, last_dm_check).await? {
            if let Some(pr) = self.internal_read(&permission, &Protocol::dms_channel(), &[&sender, &self.tenant()]).await? {
                let channel_id = serde_json::to_vec(&sender)?.hash();
                let channel_perms = PermissionSet::from_key(Path::new(protocol.hash(), vec![channel_id.clone()]), &self.com_key.derive_hash(channel_id)?)?;
                let record = Record::new(Some(), Protocol::permission_grant().hash(), serde_json::to_vec(&pr.0)?);
                self.update(record, &[&self.tenant()]).await?;
            }
        }

      //let record = Record::new(Some(ldc_id), Protocol::file().hash(), serde_json::to_vec(&DateTime::now())?);
      //self.update(record, &[&self.tenant()]).await?;

      //let payload = serde_json::to_vec(recipient)?;
      //let record_id = payload.hash();
      //let perm = self.permission_deriver.derive_permission(&record_id)?;
      //Ok(if let Some(perm_record) = self.client.read(&perm, &[recipient, &self.tenant()], true).await? {
      //    perm_record
      //} else {
      //    let record = Record::new(Some(record_id), Protocol::dms_channel().hash(), payload);
      //    let perms = self.create(None, record, &[recipient, &self.tenant()]).await?;
      //    
      ////let key = self.did_resolver.resolve_dwn_key(recipient).await?;
      //    self.client.create_did_msg(&self.keypair, recipient, perms).await?;
      //    self.read(&record_id, &[&self.tenant()]).await?.ok_or(Error::err(
      //        "Agent.establish_dms", "Failed to create dm channel"
      //    ))?
      //})
        todo!()
    }

    async fn create_did_msg(
        &self,
        sender: &DidKeyPair,
        com_key: &SecretKey,
        did_resolver: &Box<dyn DidResolver>,
        recipient: &Did,
        permission: PermissionSet,
    ) -> Result<(), Error> {
        let (_, rec_com_key) = did_resolver.resolve_dwn_keys(recipient).await?;
        let signed = SignedObject::from_keypair(sender, permission)?;
        let payload = rec_com_key.encrypt(&serde_json::to_vec(&signed)?)?;
        let request: CreateDMRequest = DwnItem::new(rec_com_key, None, payload);
        let request = DwnRequest::new(Type::DM, Action::Create, serde_json::to_vec(&request)?);

        self.request_handler.handle(&request, &[recipient]).await?;
        Ok(())
    }

    async fn read_did_msgs(
        &self,
        did_resolver: &Box<dyn DidResolver>,
        recipient: &DidKeyPair,
        rec_com_key: &SecretKey,
        timestamp: DateTime
    ) -> Result<Vec<(Did, PermissionSet)>, Error> {
        let request: ReadDMRequest = SignedObject::from_key(&recipient.secret, timestamp)?;
        let request = DwnRequest::new(Type::DM, Action::Read, serde_json::to_vec(&request)?);
        let items = self.request_handler.handle(&request, &[&recipient.public.did]).await?;
        let mut results: Vec<(Did, PermissionSet)> = Vec::new();
        for item in items {
            if item.discover != recipient.public.public_key || item.delete.is_some() {continue;}
            if let Ok(dc) = rec_com_key.decrypt(&item.payload) {
                if let Ok(signed) = serde_json::from_slice::<SignedObject<PermissionSet>>(&dc) {
                    if let Ok((Either::Left(sender), perm)) = signed.verify(&**did_resolver, None).await {
                        results.push((sender, perm));
                    }
                }
            }
        }
        Ok(results)
    }
}
