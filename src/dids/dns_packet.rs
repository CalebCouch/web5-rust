use super::Error;

use super::structs::{Did, DidMethod, DidType, DidKey, DidKeyPurpose, DidService};
use super::traits::DidDocument;
use super::DhtDocument;

use crate::common::Convert;

use crate::ed25519::PublicKey as EDPublicKey;
use simple_crypto::PublicKey;

use std::collections::BTreeMap;
use std::str::FromStr;

use simple_dns::{Packet, PacketFlag, ResourceRecord, CLASS, Name};
use simple_dns::rdata::{RData, TXT, NS};
use url::Url;

const DID_DHT_SPECIFICATION_VERSION: i32 = 0;
const DNS_RECORD_TTL: u32 = 7200;
const PROPERTY_SEPARATOR: &str = ";";
const VALUE_SEPARATOR: &str = ",";

pub struct DhtDns {}

impl DhtDns {
    fn type_to_i(r#type: &DidType) -> String {
        match r#type {
            DidType::Discoverable => 0,
            DidType::Organization => 1,
            DidType::Government => 2,
            DidType::Corporation => 3,
            DidType::LocalBusiness => 4,
            DidType::SoftwarePackage => 5,
            DidType::WebApp => 6,
            DidType::FinancialInstitution => 7,
        }.to_string()
    }

    fn i_to_type(i: &str) -> Result<DidType, Error> {
        Ok(match i {
            "0" => DidType::Discoverable,
            "1" => DidType::Organization,
            "2" => DidType::Government,
            "3" => DidType::Corporation,
            "4" => DidType::LocalBusiness,
            "5" => DidType::SoftwarePackage,
            "6" => DidType::WebApp,
            "7" => DidType::FinancialInstitution,
            _ => return Err(Error::parse("DhtDns.i_to_type", i))
        })
    }

    pub fn to_bytes(dht: &DhtDocument, gateways: Vec<Url>) -> Result<Vec<u8>, Error> {
        let mut txt_records: BTreeMap<String, String> = BTreeMap::new();

        if let Some(aka) = Some(dht.also_known_as.clone()).filter(|aka| !aka.is_empty()) {
            txt_records.insert(
                "_aka._did.".to_string(),
                aka.iter().map(|a| a.to_string()).collect::<Vec<String>>().join(VALUE_SEPARATOR)
            );
        }

        if let Some(cnt) = Some(dht.controllers.clone()).filter(|cnt| !cnt.is_empty()) {
            txt_records.insert(
                "_cnt._did.".to_string(),
                cnt.iter().map(|c| c.to_string()).collect::<Vec<String>>().join(VALUE_SEPARATOR)
            );
        }

        if let Some(typ) = Some(dht.types.clone()).filter(|typ| !typ.is_empty()) {
            txt_records.insert(
                "_typ._did.".to_string(),
                typ.iter().map(Self::type_to_i).collect::<Vec<String>>().join(VALUE_SEPARATOR)
            );
        }

        txt_records.insert(
            "_k0._did.".to_string(),
            [
                "t=0".to_string(),
                format!("k={}", Convert::Base64UrlUnpadded.encode(&dht.id_key.to_vec()))
            ].join(PROPERTY_SEPARATOR)
        );

        let keys: Vec<&DidKey> = dht.keys();
        let mut auth: Vec<String> = Vec::new();
        let mut asm: Vec<String> = Vec::new();
        let mut agm: Vec<String> = Vec::new();
        let mut inv: Vec<String> = Vec::new();
        let mut del: Vec<String> = Vec::new();

        let mut vm_ids: Vec<String> = vec!["k0".to_string()];
        for (index, key) in keys.iter().enumerate() {
            let name = format!("k{}", index+1);
            vm_ids.push(name.clone());

            if key.purposes.contains(&DidKeyPurpose::Auth) { auth.push(name.clone()); }
            if key.purposes.contains(&DidKeyPurpose::Asm) { asm.push(name.clone()); }
            if key.purposes.contains(&DidKeyPurpose::Agm) { agm.push(name.clone()); }
            if key.purposes.contains(&DidKeyPurpose::Inv) { inv.push(name.clone()); }
            if key.purposes.contains(&DidKeyPurpose::Del) { del.push(name.clone()); }

            let mut vm: BTreeMap<String, String> = BTreeMap::new();
            if key.id != key.thumbprint() { vm.insert("id".to_string(), key.id.clone()); }
            vm.insert("t".to_string(), "1".to_string());//Only Secp256k1 keys are supported
            vm.insert("k".to_string(), Convert::Base64UrlUnpadded.encode(&key.public_key.to_vec()));
            //if let Some(a) = a { vm.insert("a".to_string(), a); }
            if let Some(c) = &key.controller { vm.insert("c".to_string(), c.to_string()); }
            txt_records.insert(
                format!("_{}._did.", name),
                vm.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<String>>().join(PROPERTY_SEPARATOR)
            );
        }

        let mut svc_ids: Vec<String> = Vec::new();
        for (index, service) in dht.services().iter().enumerate() {
            let name = format!("s{}", index);
            svc_ids.push(name.clone());

            let mut ss: BTreeMap<String, String> = BTreeMap::new();
            ss.insert("id".to_string(), service.id.to_string());
            ss.insert("t".to_string(), service.types.join(VALUE_SEPARATOR));
            ss.insert(
                "se".to_string(),
                service.service_endpoints.iter().map(|se| se.to_string()).collect::<Vec<String>>().join(VALUE_SEPARATOR)
            );
            if let Some(keys) = Some(&service.keys).filter(|keys| !keys.is_empty()) {
                ss.insert("keys".to_string(), keys.join(VALUE_SEPARATOR));
            }
            txt_records.insert(
                format!("_{}._did", name),
                ss.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<String>>().join(PROPERTY_SEPARATOR)
            );
        }

        let mut root_record: BTreeMap<String, String> = BTreeMap::new();
        root_record.insert("v".to_string(), DID_DHT_SPECIFICATION_VERSION.to_string());
        root_record.insert("vm".to_string(), vm_ids.join(VALUE_SEPARATOR));
        if let Some(item) = Some(auth.join(VALUE_SEPARATOR)).filter(|item| !item.is_empty()) {
            root_record.insert("auth".to_string(), item);
        }
        if let Some(item) = Some(asm.join(VALUE_SEPARATOR)).filter(|item| !item.is_empty()) {
            root_record.insert("asm".to_string(), item);
        }
        if let Some(item) = Some(agm.join(VALUE_SEPARATOR)).filter(|item| !item.is_empty()) {
            root_record.insert("agm".to_string(), item);
        }
        if let Some(item) = Some(inv.join(VALUE_SEPARATOR)).filter(|item| !item.is_empty()) {
            root_record.insert("inv".to_string(), item);
        }
        if let Some(item) = Some(del.join(VALUE_SEPARATOR)).filter(|item| !item.is_empty()) {
            root_record.insert("del".to_string(), item);
        }
        if let Some(item) = Some(svc_ids.join(VALUE_SEPARATOR)).filter(|item| !item.is_empty()) {
            root_record.insert("svc".to_string(), item);
        }

        txt_records.insert(
            format!("_did.{}.", dht.id()),
            root_record.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<String>>().join(PROPERTY_SEPARATOR)
        );

        let mut ns_records: BTreeMap<String, String> = BTreeMap::new();
        for gateway in gateways {
            ns_records.insert(format!("_did.{}.", dht.id()), format!("{}.", gateway));
        }

        let mut packet = Packet::new_reply(0);
        packet.set_flags(PacketFlag::AUTHORITATIVE_ANSWER);
        for (name, value) in txt_records.iter() {
            packet.answers.push(
                ResourceRecord::new(
                    Name::new_unchecked(name),
                    CLASS::IN,
                    DNS_RECORD_TTL,
                    RData::TXT(TXT::new().with_string(value)?)
                )
            );
        }

        for (name, value) in ns_records.iter() {
            packet.answers.push(
                ResourceRecord::new(
                    Name::new_unchecked(name),
                    CLASS::IN,
                    DNS_RECORD_TTL,
                    RData::NS(NS(Name::new(value)?))
                )
            );

        }
        Ok(packet.build_bytes_vec()?)
    }

    pub fn from_bytes(packet: &[u8], id: &str) -> Result<DhtDocument, Error> {
        let error = || Error::parse("DhtDns.from_bytes", &hex::encode(packet));
        let packet = Packet::parse(packet)?;
        let mut txt_records: BTreeMap<String, String> = BTreeMap::new();
        for answer in packet.answers.iter() {
            if let RData::TXT(txt) = answer.rdata.clone() {
                txt_records.insert(
                    answer.name.to_string(),
                    String::try_from(txt)?
                );
            }
        }

        let also_known_as: Vec<Url> = txt_records.get("_aka._did").map(|aka|
            aka.split(VALUE_SEPARATOR).map(|a| Url::from_str(a).or(Err(error()))).collect::<Result<Vec<Url>, Error>>()
        ).unwrap_or(Ok(Vec::new()))?;

        let controllers: Vec<Did> = txt_records.get("_cnt._did").map(|cnt|
            cnt.split(VALUE_SEPARATOR).map(|c| Did::from_str(c).or(Err(error()))).collect::<Result<Vec<Did>, Error>>()
        ).unwrap_or(Ok(Vec::new()))?;

        let types: Vec<DidType> = txt_records.get("_typ._did").map(|typ|
            typ.split(VALUE_SEPARATOR).map(Self::i_to_type).collect::<Result<Vec<DidType>, Error>>()
        ).unwrap_or(Ok(Vec::new()))?;

        let root_record = txt_records.get(&format!("_did.{}", id)).ok_or(error())?;
        let root_record = root_record.split(PROPERTY_SEPARATOR).map(|kv| {
            let s: Vec<&str> = kv.split('=').collect();
            Ok((
                s.first().ok_or(error())?.to_string(),
                s.get(1).ok_or(error())?.split(VALUE_SEPARATOR).map(|i| i.to_string()).collect()
            ))
        }).collect::<Result<BTreeMap<String, Vec<String>>, Error>>()?;
        let vm_ids = root_record.get("vm").ok_or(error())?;

        //IDENTITY KEY
        if !vm_ids.contains(&"k0".to_string()) {return Err(error());};
        let k_record = txt_records.get("_k0._did").ok_or(error())?.split(PROPERTY_SEPARATOR).map(|kv| {
            let s: Vec<&str> = kv.split('=').collect();
            Ok((
                s.first().ok_or(error())?.to_string(),
                s.get(1).ok_or(error())?.to_string()
            ))
        }).collect::<Result<BTreeMap<String, String>, Error>>()?;
        if k_record.get("t").ok_or(error())? != "0" {return Err(error());}
        let bytes = &Convert::Base64UrlUnpadded.decode(k_record.get("k").ok_or(error())?)?;
        let id_key = EDPublicKey::from_bytes(bytes)?;


        let auth: Vec<String> = root_record.get("auth").unwrap_or(&Vec::new()).to_vec();
        let asm: Vec<String> = root_record.get("asm").unwrap_or(&Vec::new()).to_vec();
        let agm: Vec<String> = root_record.get("agm").unwrap_or(&Vec::new()).to_vec();
        let inv: Vec<String> = root_record.get("inv").unwrap_or(&Vec::new()).to_vec();
        let del: Vec<String> = root_record.get("del").unwrap_or(&Vec::new()).to_vec();
        let svc_ids: Vec<String> = root_record.get("svc").unwrap_or(&Vec::new()).to_vec();
        let mut keys = BTreeMap::default();
        for vm_id in vm_ids.iter() {
            if vm_id == "k0" {continue;}
            let k_record = txt_records.get(&format!("_{}._did", vm_id)).ok_or(error())?.split(PROPERTY_SEPARATOR).map(|kv| {
                let s: Vec<&str> = kv.split('=').collect();
                Ok((
                    s.first().ok_or(error())?.to_string(),
                    s.get(1).ok_or(error())?.to_string()
                ))
            }).collect::<Result<BTreeMap<String, String>, Error>>()?;
            let t = k_record.get("t").ok_or(error())?;
            if t != "1" {return Err(error());}
            let bytes = &Convert::Base64UrlUnpadded.decode(k_record.get("k").ok_or(error())?)?;
            let public_key = PublicKey::from_bytes(bytes)?;
            let controller = match k_record.get("c") {
                None => None,
                Some(c) => Some(Did::from_str(c)?)
            };
            let purposes: Vec<DidKeyPurpose> = vec![
                Some(DidKeyPurpose::Auth).filter(|_| auth.contains(vm_id)),
                Some(DidKeyPurpose::Asm).filter(|_| asm.contains(vm_id)),
                Some(DidKeyPurpose::Agm).filter(|_| agm.contains(vm_id)),
                Some(DidKeyPurpose::Inv).filter(|_| inv.contains(vm_id)),
                Some(DidKeyPurpose::Del).filter(|_| del.contains(vm_id)),
            ].into_iter().flatten().collect();

            let key_id = k_record.get("id").cloned();
            let key = DidKey::new(key_id, Did::new(DidMethod::DHT, id.to_string()), public_key, purposes, controller);
            keys.insert(key.id.clone(), key);
        }

        let mut services = BTreeMap::default();
        for svc_id in svc_ids.iter() {
            let s_record = txt_records.get(&format!("_{}._did", svc_id)).ok_or(error())?.split(PROPERTY_SEPARATOR).map(|kv| {
                let s: Vec<&str> = kv.split('=').collect();
                Ok((
                    s.first().ok_or(error())?.to_string(),
                    s.get(1).ok_or(error())?.to_string()
                ))
            }).collect::<Result<BTreeMap<String, String>, Error>>()?;
            let id = s_record.get("id").ok_or(error())?.to_string();//TODO: too lax? must be a URL?
            let types = s_record.get("t").ok_or(error())?.split(VALUE_SEPARATOR).map(|s| s.to_string()).collect();
            let service_endpoints = s_record.get("se").ok_or(error())?.split(VALUE_SEPARATOR).map(|s| s.to_string()).collect::<Vec<String>>();
            let keys = s_record.get("keys").map(|keys| keys.split(VALUE_SEPARATOR).map(|s| s.to_string()).collect()).unwrap_or_default();

            services.insert(id.clone(), DidService{id, types, service_endpoints, keys});
        }
        Ok(DhtDocument::new(id_key, also_known_as, controllers, services, keys, types))
    }
}
