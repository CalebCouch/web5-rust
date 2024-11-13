use super::Error;

use super::structs::{Tasks, Task};
use super::compiler::CompilerMemory;

use crate::dids::{DidResolver, Endpoint, Did};

use std::any::Any;

use dyn_clone::{clone_trait_object, DynClone};
use downcast_rs::DowncastSync;
use erased_serde::Serialize;
use uuid::Uuid;

#[async_trait::async_trait]
pub trait Command<'a>: TypeDebug + std::fmt::Debug + Serialize + Send + Sync + DynClone {
    async fn process(
        self: Box<Self>, uuid: Uuid, ep: Endpoint, memory: &mut CompilerMemory<'a>
    ) -> Result<Vec<(Uuid, Task<'a>)>, Error>;

    fn serialize(&self) -> String {
        let mut buffer = std::io::BufWriter::new(Vec::<u8>::new());
        let serializer = &mut serde_json::ser::Serializer::new(&mut buffer);
        self.erased_serialize(&mut Box::new(<dyn erased_serde::Serializer>::erase(
            serializer
        ))).unwrap();
        format!(
            "{}::{}",
            (*self).get_type(),
            std::str::from_utf8(&buffer.into_inner().unwrap()).unwrap()
        )
    }

    async fn get_endpoints(
        &self, dids: Vec<Did>, did_resolver: &dyn DidResolver
    ) -> Result<Vec<Endpoint>, Error> {
        let endpoints = did_resolver.get_endpoints(&dids).await?;
        if endpoints.is_empty() {panic!("Did set had no endpoints");}
        Ok(endpoints)
    }
}
erased_serde::serialize_trait_object!(for<'a> Command<'a>);
clone_trait_object!(for<'a> Command<'a>);

pub trait TypeDebug: std::fmt::Debug {
    fn get_full_type(&self) -> String {
        std::any::type_name_of_val(self).to_string()
    }
    fn get_type(&self) -> String {
        let full_type = self.get_full_type();
        let split = full_type.split("::").collect::<Vec<_>>();
        split[split.len()-1].to_string().replace(">", "")
    }

    fn debug(&self) -> String {
        format!("{}::{:?}", self.get_type(), self)
    }

    fn truncate_debug(&self) -> String {
        let debug = format!("{:?}", self);
        let debug = if debug.len() > 100 {&debug[..100]} else {&debug};
        format!("{}::{}", self.get_type(), debug)
    }
}

impl<T: std::fmt::Debug> TypeDebug for T {}

pub trait Response: Any + std::fmt::Debug + DowncastSync + DynClone + Serialize + TypeDebug {}
erased_serde::serialize_trait_object!(Response);
clone_trait_object!(Response);


impl<T: Any + std::fmt::Debug + Clone + Sync + Send + Serialize + TypeDebug> Response for T {}
downcast_rs::impl_downcast!(sync Response);
