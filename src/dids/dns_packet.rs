use super::error::Error;
use super::did_core::{Did, Type, Key, Purpose, Service, Url};
use super::did_dht::{DidDht, DhtKey};
use crate::crypto::{PublicKey, Curve};
use crate::common::Convert;
use super::did_method::DidMethod;

use std::collections::HashMap;

use simple_dns::{Packet, PacketFlag, ResourceRecord, CLASS, Name};
use simple_dns::rdata::{RData, TXT, NS};

const DID_DHT_SPECIFICATION_VERSION: i32 = 0;
const DNS_RECORD_TTL: u32 = 7200;
const PROPERTY_SEPARATOR: &str = ";";
const VALUE_SEPARATOR: &str = ",";

pub struct DhtDns {}

impl DhtDns {
    fn key_to_ta(key: &PublicKey) -> (u8, Option<String>) {
        match key {
            PublicKey::Ed(_) => (0, None),
            PublicKey::K1(_) => (1, Some("ES256K".to_string())),
            PublicKey::R1(_) => (2, Some("ES256".to_string()))
        }
    }

    fn key_to_t(key: &PublicKey) -> u8 {
        match key {
            PublicKey::Ed(_) => 0,
            PublicKey::K1(_) => 1,
            PublicKey::R1(_) => 2
        }
    }

    fn kt_to_key(k: &str, t: &str) -> Result<PublicKey, Error> {
        let bytes = Convert::Base64UrlUnpadded.decode(k)?;
        let curve = match t {
            "0" => Curve::Ed,
            "1" => Curve::K1,
            "2" => Curve::R1,
            _ => {return Err(Error::Parse("Curve".to_string(), t.to_string()));}
        };
        Ok(PublicKey::from_bytes(curve, &bytes)?)
    }

    fn type_to_i(r#type: &Type) -> String {
        match r#type {
            Type::Discoverable => 0,
            Type::Organization => 1,
            Type::Government => 2,
            Type::Corporation => 3,
            Type::LocalBusiness => 4,
            Type::SoftwarePackage => 5,
            Type::WebApp => 6,
            Type::FinancialInstitution => 7,
        }.to_string()
    }

    fn i_to_type(i: &str) -> Result<Type, Error> {
        Ok(match i {
            "0" => Type::Discoverable,
            "1" => Type::Organization,
            "2" => Type::Government,
            "3" => Type::Corporation,
            "4" => Type::LocalBusiness,
            "5" => Type::SoftwarePackage,
            "6" => Type::WebApp,
            "7" => Type::FinancialInstitution,
            _ => return Err(Error::Parse("dht type".to_string(), i.to_string()))
        })
    }

    pub fn to_bytes(dht: &DidDht, gateways: Vec<Url>) -> Result<Vec<u8>, Error> {
        let mut txt_records: HashMap<String, String> = HashMap::new();

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

        let keys: Vec<Key> = [vec![dht.identity_key.to_key()], dht.keys.clone()].concat();
        let mut auth: Vec<String> = Vec::new();
        let mut asm: Vec<String> = Vec::new();
        let mut agm: Vec<String> = Vec::new();
        let mut inv: Vec<String> = Vec::new();
        let mut del: Vec<String> = Vec::new();

        let mut vm_ids: Vec<String> = Vec::new();
        for (index, key) in keys.iter().enumerate() {
            let name = format!("k{}", index);
            vm_ids.push(name.clone());

            if key.purposes.contains(&Purpose::Auth) { auth.push(name.clone()); }
            if key.purposes.contains(&Purpose::Asm) { asm.push(name.clone()); }
            if key.purposes.contains(&Purpose::Agm) { agm.push(name.clone()); }
            if key.purposes.contains(&Purpose::Inv) { inv.push(name.clone()); }
            if key.purposes.contains(&Purpose::Del) { del.push(name.clone()); }

            let mut vm: HashMap<String, String> = HashMap::new();
            if let Some(id) = &key.id { vm.insert("id".to_string(), id.clone()); }
            let t = Self::key_to_t(&key.public_key);
            vm.insert("t".to_string(), t.to_string());
            vm.insert("k".to_string(), Convert::Base64UrlUnpadded.encode(key.public_key.as_bytes()));
            //if let Some(a) = a { vm.insert("a".to_string(), a); }
            if let Some(c) = &key.controller { vm.insert("c".to_string(), c.to_string()); }
            txt_records.insert(
                format!("_{}._did.", name),
                vm.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<String>>().join(PROPERTY_SEPARATOR)
            );
        }

        let mut svc_ids: Vec<String> = Vec::new();
        for (index, service) in dht.services.iter().enumerate() {
            let name = format!("s{}", index);
            svc_ids.push(name.clone());

            let mut ss: HashMap<String, String> = HashMap::new();
            ss.insert("id".to_string(), service.id.to_string());
            ss.insert("t".to_string(), service.types.join(VALUE_SEPARATOR));
            ss.insert(
                "se".to_string(),
                service.service_endpoints.iter().map(|se| se.to_string()).collect::<Vec<String>>().join(VALUE_SEPARATOR)
            );
            if let Some(enc) = Some(&service.enc).filter(|enc| !enc.is_empty()) {
                ss.insert("enc".to_string(), enc.join(VALUE_SEPARATOR));
            }
            if let Some(sig) = Some(&service.sig).filter(|sig| !sig.is_empty()) {
                ss.insert("sig".to_string(), sig.join(VALUE_SEPARATOR));
            }
            txt_records.insert(
                format!("_{}._did", name),
                ss.iter().map(|(k, v)| format!("{}={}", k, v)).collect::<Vec<String>>().join(PROPERTY_SEPARATOR)
            );
        }

        let mut root_record: HashMap<String, String> = HashMap::new();
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

        let mut ns_records: HashMap<String, String> = HashMap::new();
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

    pub fn from_bytes(packet: &[u8], id: String) -> Result<DidDht, Error> {
        let error = || Error::Parse("dht dns packet".to_string(), hex::encode(packet));
        let packet = Packet::parse(packet)?;
        let mut txt_records: HashMap<String, String> = HashMap::new();
        for answer in packet.answers.iter() {
            if let RData::TXT(txt) = answer.rdata.clone() {
                txt_records.insert(
                    answer.name.to_string(),
                    String::try_from(txt)?
                );
            }
        }

        let also_known_as: Vec<Url> = txt_records.get("_aka._did").map(|aka|
            aka.split(VALUE_SEPARATOR).map(|a| Url::parse(a).or(Err(error()))).collect::<Result<Vec<Url>, Error>>()
        ).unwrap_or(Ok(Vec::new()))?;

        let controllers: Vec<Did> = txt_records.get("_cnt._did").map(|cnt|
            cnt.split(VALUE_SEPARATOR).map(|c| Did::parse(c).or(Err(error()))).collect::<Result<Vec<Did>, Error>>()
        ).unwrap_or(Ok(Vec::new()))?;

        let types: Vec<Type> = txt_records.get("_typ._did").map(|typ|
            typ.split(VALUE_SEPARATOR).map(Self::i_to_type).collect::<Result<Vec<Type>, Error>>()
        ).unwrap_or(Ok(Vec::new()))?;

        let root_record = txt_records.get(&format!("_did.{}", id)).ok_or(error())?;
        let root_record = root_record.split(PROPERTY_SEPARATOR).map(|kv| {
            let s: Vec<&str> = kv.split('=').collect();
            Ok((
                s.first().ok_or(error())?.to_string(),
                s.get(1).ok_or(error())?.split(VALUE_SEPARATOR).map(|i| i.to_string()).collect()
            ))
        }).collect::<Result<HashMap<String, Vec<String>>, Error>>()?;
        let vm_ids = root_record.get("vm").ok_or(error())?;
        let auth: Vec<String> = root_record.get("auth").unwrap_or(&Vec::new()).to_vec();
        let asm: Vec<String> = root_record.get("asm").unwrap_or(&Vec::new()).to_vec();
        let agm: Vec<String> = root_record.get("agm").unwrap_or(&Vec::new()).to_vec();
        let inv: Vec<String> = root_record.get("inv").unwrap_or(&Vec::new()).to_vec();
        let del: Vec<String> = root_record.get("del").unwrap_or(&Vec::new()).to_vec();
        let svc_ids: Vec<String> = root_record.get("svc_ids").unwrap_or(&Vec::new()).to_vec();

        let mut keys = vm_ids.iter().map(|vm_id| -> Result<Key, Error> {
            let k_record = txt_records.get(&format!("_{}._did", vm_id)).ok_or(error())?.split(PROPERTY_SEPARATOR).map(|kv| {
                let s: Vec<&str> = kv.split('=').collect();
                Ok((
                    s.first().ok_or(error())?.to_string(),
                    s.get(1).ok_or(error())?.to_string()
                ))
            }).collect::<Result<HashMap<String, String>, Error>>()?;
            let t = k_record.get("t").ok_or(error())?;
            let k = k_record.get("k").ok_or(error())?;
            let public_key = Self::kt_to_key(k, t)?;
            let controller = match k_record.get("c") {
                None => None,
                Some(c) => Some(Did::parse(c)?)
            };
            let purposes: Vec<Purpose> = vec![
                Some(Purpose::Auth).filter(|_| auth.contains(vm_id)),
                Some(Purpose::Asm).filter(|_| asm.contains(vm_id)),
                Some(Purpose::Agm).filter(|_| agm.contains(vm_id)),
                Some(Purpose::Inv).filter(|_| inv.contains(vm_id)),
                Some(Purpose::Del).filter(|_| del.contains(vm_id)),
            ].into_iter().flatten().collect();
            let id = k_record.get("id").cloned();
            Ok(Key{id, public_key, purposes, controller})
        }).collect::<Result<Vec<Key>, Error>>()?;
        let index = keys.iter().position(|k| k.id == Some("0".to_string())).ok_or(error())?;
        let identity_key = DhtKey::from_key(keys.remove(index))?;

        let services = svc_ids.iter().map(|svc_id| {
            let s_record = txt_records.get(&format!("_{}._did", svc_id)).ok_or(error())?.split(PROPERTY_SEPARATOR).map(|kv| {
                let s: Vec<&str> = kv.split('=').collect();
                Ok((
                    s.first().ok_or(error())?.to_string(),
                    s.get(1).ok_or(error())?.to_string()
                ))
            }).collect::<Result<HashMap<String, String>, Error>>()?;
            let id = Url::parse(s_record.get("id").ok_or(error())?)?;
            let types = s_record.get("t").ok_or(error())?.split(VALUE_SEPARATOR).map(|s| s.to_string()).collect();
            let service_endpoints = s_record.get("se").ok_or(error())?.split(VALUE_SEPARATOR).map(|se| Ok(Url::parse(se)?)).collect::<Result<Vec<Url>, Error>>()?;
            let enc = s_record.get("enc").map(|enc| enc.split(VALUE_SEPARATOR).map(|s| s.to_string()).collect()).unwrap_or(Vec::new());
            let sig = s_record.get("sig").map(|sig| sig.split(VALUE_SEPARATOR).map(|s| s.to_string()).collect()).unwrap_or(Vec::new());

            Ok(Service{id, types, service_endpoints, enc, sig})
        }).collect::<Result<Vec<Service>, Error>>()?;

        Ok(DidDht{identity_key, also_known_as, controllers, services, keys, types})
    }
}
