use super::Error;

use super::traits::{KeyValueStore, Indexable};

use crate::common::structs::{DateTime, Uuid};

use crate::crypto::traits::{Hashable};

use std::path::PathBuf;
use std::collections::BTreeMap;
use std::cmp::Ordering;

use serde::{Serialize, Deserialize};
use schemars::JsonSchema;

#[derive(JsonSchema, Serialize, Deserialize, Clone, PartialEq)]
pub enum Value {
    I64(i64),
    U64(u64),
    F64(f64),
    r#String(String),
    Bool(bool),
    Array(Vec<Value>)
}

impl Value {
    pub fn as_i64(&self) -> Option<&i64> {if let Value::I64(val) = &self {Some(val)} else {None}}
    pub fn as_u64(&self) -> Option<&u64> {if let Value::U64(val) = &self {Some(val)} else {None}}
    pub fn as_f64(&self) -> Option<&f64> {if let Value::F64(val) = &self {Some(val)} else {None}}
    pub fn as_string(&self) -> Option<&String> {if let Value::r#String(val) = &self {Some(val)} else {None}}
    pub fn as_bool(&self) -> Option<&bool> {if let Value::Bool(val) = &self {Some(val)} else {None}}
    pub fn as_array(&self) -> Option<&Vec<Value>> {if let Value::Array(val) = &self {Some(val)} else {None}}

    pub fn contains(&self, other: &Value) -> Option<bool> {
        self.as_array().map(|v| v.contains(other))
    }

    pub fn starts_with(&self, other: &Value) -> Option<bool> {
        if let Some(other) = other.as_string() {
            self.as_string().map(|s| s.starts_with(other))
        } else {None}
    }

    fn cmp(&self, other: &Value, cmp_type: &CmpType) -> Option<bool> {
        if *cmp_type == CmpType::E {
            Some(self == other)
        } else {
            self.partial_cmp(other).map(|ordering| {
                match cmp_type {
                    CmpType::GT if (ordering as i8) > 0 => true,
                    CmpType::GTE if (ordering as i8) >= 0 => true,
                    CmpType::LT if (ordering as i8) < 0 => true,
                    CmpType::LTE if (ordering as i8) <= 0 => true,
                    _ => false
                }
            })
        }
    }
}

impl PartialOrd for Value {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        match self {
            Value::I64(val) => other.as_i64().map(|oval| val.cmp(oval)),
            Value::U64(val) => other.as_u64().map(|oval| val.cmp(oval)),
            Value::F64(val) => other.as_f64().map(|oval| val.total_cmp(oval)),
            Value::r#String(val) => other.as_string().map(|oval| val.cmp(oval)),
            Value::Bool(val) => other.as_bool().map(|oval| val.cmp(oval)),
            Value::Array(_) => None
        }
    }
}

impl From<i64> for Value {fn from(v: i64) -> Self {Value::I64(v)}}
impl From<u64> for Value {fn from(v: u64) -> Self {Value::U64(v)}}
impl From<usize> for Value {fn from(v: usize) -> Self {Value::U64(v as u64)}}
impl From<DateTime> for Value {fn from(v: DateTime) -> Self {Value::U64(v.timestamp())}}
impl From<u8> for Value {fn from(v: u8) -> Self {Value::U64(v as u64)}}
impl From<f64> for Value {fn from(v: f64) -> Self {Value::F64(v)}}
impl From<String> for Value {fn from(v: String) -> Self {Value::r#String(v)}}
impl From<bool> for Value {fn from(v: bool) -> Self {Value::Bool(v)}}
impl<V: Into<Value>> From<Vec<V>> for Value {fn from(v: Vec<V>) -> Self {Value::Array(v.into_iter().map(|v| v.into()).collect())}}

impl std::fmt::Debug for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::I64(i) => write!(f, "{}", i),
            Value::U64(u) => write!(f, "{}", u),
            Value::F64(_f) => write!(f, "{}", _f),
            Value::r#String(s) => write!(f, "{}", s),
            Value::Bool(b) => write!(f, "{}", b),
            Value::Array(vec) => write!(f, "{:#?}", vec)
        }
    }
}


#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum CmpType { GT, GTE, E, LT, LTE }

#[derive(JsonSchema, Serialize, Deserialize, Clone, Debug, PartialEq)]
pub enum Filter {
    Cmp(Value, CmpType),
    Contains(Value),
    StartsWith(Value),
    All(Vec<Filter>),
    Any(Vec<Filter>),
    Not(Box<Filter>)

}

impl Filter {
    pub fn filter(&self, item: &Value) -> Option<bool> {
        match self {
            Filter::Cmp(value, cmp_type) => item.cmp(value, cmp_type),
            Filter::Contains(value) => item.contains(value),
            Filter::StartsWith(value) => item.starts_with(value),
            Filter::All(filters) => {
                for filter in filters {
                    if let Some(b) = filter.filter(item) {
                        if !b {
                            return Some(true);
                        }
                    } else {return None;}
                }
                Some(false)
            },
            Filter::Any(filters) => {
                for filter in filters {
                    if let Some(b) = filter.filter(item) {
                        if b {
                            return Some(true);
                        }
                    } else {return None;}
                }
                Some(false)
               },
            Filter::Not(filter) => filter.filter(item).map(|f| !f)
        }
    }

    pub fn contains<V: Into<Value>>(val: V) -> Filter {
        Filter::Contains(val.into())
    }
    pub fn range<V: Into<Value>>(start: V, end: V) -> Filter {
        Filter::All(vec![Filter::Cmp(start.into(), CmpType::GTE), Filter::Cmp(end.into(), CmpType::LTE)])
    }
    pub fn new_not(filter: Filter) -> Filter {Filter::Not(Box::new(filter))}
    pub fn cmp<V: Into<Value>>(cmp: CmpType, val: V) -> Filter {Filter::Cmp(val.into(), cmp)}
    pub fn equal<V: Into<Value>>(val: V) -> Filter {Filter::Cmp(val.into(), CmpType::E)}
    pub fn is_equal(&self) -> bool {
        if let Filter::Cmp(_, t) = self {
            *t == CmpType::E
        } else {false}
    }
}

pub type Index = BTreeMap<String, Value>;

#[derive(Default)]
pub struct IndexBuilder {
    indexes: Vec<(String, Value)>
}
impl IndexBuilder {
    pub fn new() -> Self {Self::default()}
    pub fn add<V: Into<Value>>(&mut self, p: &str, v: V) {
        self.indexes.push((p.to_string(), v.into()));
    }
    pub fn finish(self) -> Index {
        Index::from_iter(self.indexes)
    }
}

pub type Filters = BTreeMap<String, Filter>;

pub struct FiltersBuilder {}
impl FiltersBuilder {
    pub fn add(filters: &mut Filters, property: &str, ad_filter: Filter) {
        if let Some(filter) = filters.get_mut(property) {
            if let Filter::All(ref mut filters) = filter {
                filters.push(ad_filter);
            } else {
                *filter = Filter::All(vec![filter.clone(), ad_filter]);
            }
        } else {
            filters.insert(property.to_string(), ad_filter);
        }
    }
    pub fn combine(a_filters: &Filters, b_filters: &Filters, or: bool) -> Filters {
        let mut filters = Vec::new();
        for (a_name, a_filter) in a_filters {
            if let Some(b_filter) = b_filters.get(a_name) {
                let vec = vec![b_filter.clone(), a_filter.clone()];
                filters.push((a_name.to_string(), if or {Filter::Any(vec)} else {Filter::All(vec)}));
            } else {
                filters.push((a_name.to_string(), a_filter.clone()));
            }
        }
        for (b_name, b_filter) in b_filters {
            if !a_filters.contains_key(b_name) {
                filters.push((b_name.to_string(), b_filter.clone()));
            }
        }
        Filters::from_iter(filters)
    }
    pub fn build(vec: Vec<(&str, Filter)>) -> Filters {
        Filters::from_iter(vec.into_iter().map(|(k, f)| (k.to_string(), f)))
    }
}

#[derive(JsonSchema, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub enum SortDirection {
  Descending = -1,
  Ascending = 1
}

#[derive(JsonSchema, Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SortOptions {
    direction: SortDirection,
    property: String,
    limit: Option<usize>,
    cursor_key: Option<Vec<u8>>
}

impl SortOptions {
    pub fn new(property: &str) -> Self {
        SortOptions{
            direction: SortDirection::Ascending,
            property: property.to_string(),
            limit: None,
            cursor_key: None
        }
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct UuidKeyed<O: Indexable + Hashable> {
    pub inner: O
}

impl<O: Indexable + Serialize + for<'a> Deserialize<'a>> Hashable for UuidKeyed<O> {}
impl<O: Indexable + Serialize + for<'a> Deserialize<'a> + Hashable> Indexable for UuidKeyed<O> {
    const PRIMARY_KEY: &'static str = "uuid";
    const DEFAULT_SORT: &'static str = O::DEFAULT_SORT;
    fn primary_key(&self) -> Vec<u8> {Uuid::new().to_vec()}
    fn secondary_keys(&self) -> Index {
        let mut index = self.inner.secondary_keys();
        index.insert(
            O::PRIMARY_KEY.to_string(),
            self.inner.primary_key().into()
        );
        index
    }
}

#[derive(Debug, Clone)]
pub struct Database {
    store: Box<dyn KeyValueStore>,
    location: PathBuf
}

pub const MAIN: &str = "___main___";
pub const INDEX: &str = "___index___";
pub const ALL: &str = "ALL";

impl Database {
    pub fn location(&self) -> PathBuf {self.location.clone()}
    pub fn new<KVS: KeyValueStore + 'static>(location: PathBuf) -> Result<Self, Error> {
        Ok(Database{store: Box::new(KVS::new(location.clone())?), location})
    }

    pub fn get_raw(&self, path: Option<PathBuf>, pk: &[u8]) -> Result<Option<Vec<u8>>, Error> {
        let path = path.unwrap_or_default();
        Ok(self.store.get_partition(self.location.join(path).join(MAIN))
            .map(|db| db.get(pk)).transpose()?.flatten())
    }

    pub fn get<I: Indexable + for<'a> Deserialize<'a>>(&self, path: Option<PathBuf>, pk: &[u8]) -> Result<Option<I>, Error> {
        Ok(self.get_raw(path, pk)?.map(|item| {
            serde_json::from_slice::<I>(&item)
        }).transpose()?)
    }

    pub fn get_all<I: Indexable + for<'a> Deserialize<'a>>(&self, path: Option<PathBuf>) -> Result<Vec<I>, Error> {
        let path = path.unwrap_or_default();
        Ok(if let Some(db) = self.store.get_partition(self.location.join(path).join(MAIN)) {
            db.values()?.into_iter().map(|item| Ok::<I, Error>(serde_json::from_slice::<I>(&item)?)).collect::<Result<Vec<I>, Error>>()?
        } else {Vec::new()})
    }

    pub fn keys(&self, path: Option<PathBuf>) -> Result<Vec<Vec<u8>>, Error> {
        let path = path.unwrap_or_default();
        Ok(if let Some(db) = self.store.get_partition(self.location.join(path).join(MAIN)) {
            db.keys()?
        } else {Vec::new()})
    }

    fn add(partition: &mut dyn KeyValueStore, key: &[u8], value: Vec<u8>) -> Result<(), Error> {
        if let Some(values) = partition.get(key)? {
            let mut values: Vec<Vec<u8>> = serde_json::from_slice(&values)?;
            values.push(value);
            partition.set(key, &serde_json::to_vec(&values)?)?;
        } else {
            partition.set(key, &serde_json::to_vec(&vec![value])?)?;
        }
        Ok(())
    }

    fn remove(partition: &mut dyn KeyValueStore, key: &[u8], value: &[u8]) -> Result<(), Error> {
        if let Some(values) = partition.get(key)? {
            let mut values: Vec<Vec<u8>> = serde_json::from_slice(&values)?;
            values.retain(|v| v != value);
            if !values.is_empty() {
                partition.set(key, &serde_json::to_vec(&values)?)?;
            } else {
                partition.delete(key)?;
            }
        }
        Ok(())
    }

    pub fn set<I: Indexable + Serialize>(&mut self, path: Option<PathBuf>, item: &I) -> Result<(), Error> {
        let path = path.unwrap_or_default();
        let pk = item.primary_key();
        self.delete(Some(path.clone()), &pk)?;
        let db = self.store.partition(self.location.join(path.clone()))?;
        let mut keys = item.secondary_keys();
        keys.insert(I::PRIMARY_KEY.to_string(), pk.clone().into());
        keys.insert("timestamp_stored".to_string(), DateTime::now().into());
        db.partition(PathBuf::from(MAIN))?.set(&pk, &serde_json::to_vec(item)?)?;
        db.partition(PathBuf::from(INDEX))?.set(&pk, &serde_json::to_vec(&keys)?)?;
        for (key, value) in keys.iter() {
            let partition = db.partition(PathBuf::from(&format!("__{}__", key)))?;
            let value = serde_json::to_vec(&value)?;
            Self::add(partition, &value, pk.clone())?;
            Self::add(partition, ALL.as_bytes(), pk.clone())?;
        }
        Ok(())
    }

    pub fn delete(&mut self, path: Option<PathBuf>, pk: &[u8]) -> Result<(), Error> {
        let path = path.unwrap_or_default();
        let db = self.store.partition(self.location.join(path))?;
        db.partition(PathBuf::from(MAIN))?.delete(pk)?;
        if let Some(index) = db.partition(PathBuf::from(INDEX))?.get(pk)? {
            let keys: Index = serde_json::from_slice(&index)?;
            for (key, value) in keys.iter() {
                let partition = db.partition(PathBuf::from(&format!("__{}__", key)))?;
                let value = serde_json::to_vec(value)?;
                Self::remove(partition, &value, pk)?;
                Self::remove(partition, ALL.as_bytes(), pk)?;
            }
        }
        Ok(())
    }

    pub fn clear(&mut self, path: Option<PathBuf>) -> Result<(), Error> {
        let path = path.unwrap_or_default();
        self.store.partition(self.location.join(path))?.clear()?;
        Ok(())
    }

    pub fn query<I: Indexable + for<'a> Deserialize<'a>>(
        &self,
        path: Option<PathBuf>,
        filters: &Filters,
        sort_options: Option<SortOptions>
    ) -> Result<(Vec<I>, Option<Vec<u8>>), Error> {
        let path = path.unwrap_or_default();
        let sort_options = sort_options.unwrap_or(SortOptions::new(I::DEFAULT_SORT));
        let none = || Ok((Vec::new(), None));
        let db = if let Some(p) = self.store.get_partition(self.location.join(path)) {p} else {return none();};

        let db_filters: Vec<String> = filters.iter().filter_map(|(p, f)|
            Some(p.to_string()).filter(|_| f.is_equal())
        ).collect();

        let partition_name = PathBuf::from(format!("__{}__",
            db_filters.first().unwrap_or(&sort_options.property)
        ));
        let partition = if let Some(p) = db.get_partition(partition_name) {p} else {return none();};
        let index = if let Some(p) = db.get_partition(PathBuf::from(INDEX)) {p} else {return none();};

        let all = if let Some(p) = partition.get(ALL.as_bytes())? {
            serde_json::from_slice::<Vec<Vec<u8>>>(&p)?
        } else {return none();};
        let mut values = all.into_iter().map(|pk| {
            let keys = index.get(&pk)?.ok_or(
                Error::err("database.query", "Indexed value not found in index")
            )?;
            Ok((pk, serde_json::from_slice(&keys)?))
        }).collect::<Result<Vec<(Vec<u8>, Index)>, Error>>()?
        .into_iter().filter(|(_, keys)| {
            filters.iter().all(|(prop, filter)| {
                if let Some(value) = keys.get(prop) {
                    filter.filter(value).unwrap_or(false)
                } else {false}
            })
        }).collect::<Vec<(Vec<u8>, Index)>>().into_iter().map(|(pk, mut keys)| {
             let main = db.get_partition(PathBuf::from(MAIN)).ok_or(
                Error::err("database.query", "Indexed value not found in main")
            )?;
            let sp = keys.remove(&sort_options.property).ok_or(
                Error::err("database.query", "Sort property not found in matched value")
            )?;

            Ok(main.get(&pk)?.map(|i| (i, sp)))
        }).collect::<Result<Vec<Option<(Vec<u8>, Value)>>, Error>>()?
        .into_iter().flatten()
        .collect::<Vec<(Vec<u8>, Value)>>();

        values.sort_by(|a, b| {
            if sort_options.direction == SortDirection::Ascending {
                a.1.partial_cmp(&b.1).unwrap_or(Ordering::Equal)
            } else {
                b.1.partial_cmp(&a.1).unwrap_or(Ordering::Equal)
            }
        });

        let start = sort_options.cursor_key.and_then(|ck|
            values.iter().position(|(i, _)| *i == ck).map(|p| p+1)
        ).unwrap_or(0);
        let end = sort_options.limit.map(|l| start+l).unwrap_or(values.len());
        let cursor = if end != values.len() {Some(values[end].0.clone())} else {None};
        if start == end {
            Ok((Vec::new(), None))
        } else {
            Ok((values[start..end].iter().cloned().flat_map(|(item, _)|
                serde_json::from_slice(&item).ok()
            ).collect::<Vec<I>>(),
            cursor))
        }
    }
}
