use super::Error;

use crate::common::traits::KeyValueStore;

use std::cmp::Ordering;
use std::collections::{HashSet, BTreeMap};

use serde::{Serialize, Deserialize};
use serde_json::to_vec as serialize;
use serde_json::from_slice as deserialize;

const INDEX_SUBLEVEL_NAME: &str = "index";

#[derive(Serialize, Deserialize, Debug, Clone, Eq, Hash, PartialEq)]
pub struct KeyValues {
    map: BTreeMap<String, Vec<String>>
}

impl KeyValues {
    pub fn map(&self) -> &BTreeMap<String, Vec<String>> {&self.map}
    pub fn values(&self) -> Vec<&Vec<String>> {self.map.values().collect()}
    pub fn is_empty(&self) -> bool {self.map.is_empty()}
    pub fn get(&self, key: &str) -> Option<&Vec<String>> {self.map.get(key)}

    pub fn from(map: Vec<(&str, String)>) -> Result<KeyValues, Error> {
        if map.is_empty() {return Err(Error::bad_request("KeyValues.from", "map must not be empty"));}
        Ok(KeyValues{map: BTreeMap::from_iter(map.into_iter().map(|(k, v)| (k.to_string(), vec![v])))})
    }
    pub fn insert(&mut self, key: &str, value: String) {
        self.map.insert(key.to_string(), vec![value]);
    }
    pub fn insert_vec(&mut self, key: &str, value: Vec<String>) -> Result<(), Error> {
        if self.map.is_empty() {return Err(Error::bad_request("KeyValues.insert_vec", "value must not be empty"));}
        self.map.insert(key.to_string(), value);
        Ok(())
    }
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum CmpType { GT, GTE, LT, LTE, E}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct CmpFilter {
    range: CmpType,
    value: String
}

impl CmpFilter {
    pub fn new(range: CmpType, value: String) -> CmpFilter {CmpFilter{range, value}}

    pub fn filter(&self, item: &String) -> bool {
        let ordering = self.value.cmp(item);
        match self.range {
            CmpType::GT if (ordering as i8) > 0 => true,
            CmpType::GTE if (ordering as i8) >= 0 => true,
            CmpType::E if (ordering as i8) == 0 => true,
            CmpType::LT if (ordering as i8) < 0 => true,
            CmpType::LTE if (ordering as i8) <= 0 => true,
            _ => false
        }
    }
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub enum Filter {
    HasField,
    StartsWith(String),
    Equal(String),
    OneOf(Vec<String>),
    Cmp(CmpFilter),
    And(Vec<Filter>),
    Or(Vec<Filter>)
}

impl Filter {
    pub fn filter(&self, item: &String) -> bool {
        match self {
            Self::HasField => true, //If filter gets called then the required property exists
            Self::StartsWith(value) if item.starts_with(value) => true,
            Self::Equal(value) if item == value => true,
            Self::OneOf(values) if values.contains(item) => true,
            Self::Cmp(filter) if filter.filter(item) => true,
            Self::And(filters) if filters.iter().all(|f| f.filter(item)) => true,
            Self::Or(filters) if filters.iter().any(|f| f.filter(item)) => true,
            _ => false
        }
    }
}

#[derive(Debug, Clone, Eq, Hash, PartialEq)]
pub struct PropertyFilter {
    pub filters: BTreeMap<String, Filter>
}

impl PropertyFilter {
    pub fn new(filters: BTreeMap<String, Filter>) -> Result<PropertyFilter, Error> {
        if filters.is_empty() {return Err(Error::bad_request("PropertyFilter", "filters must not be empty"));}
        Ok(PropertyFilter{filters: filters})
    }
    pub fn from_vec(vec: Vec<(&str, Filter)>) -> Result<PropertyFilter, Error> {
        Ok(Self::new(BTreeMap::from_iter(vec.into_iter().map(|(k, v)| (k.to_string(), v))))?)
    }
    pub fn insert(&mut self, name: &str, value: Filter) {
        self.filters.insert(name.to_string(), value);
    }

    pub fn get_filters(&self) -> Vec<(&String, &Filter)> {
        self.filters.iter().collect()
    }
    pub fn get(&self, key: &str) -> Option<&Filter> {
        self.filters.get(key)
    }
    pub fn get_most_narrow_index(&self) -> String {
        if self.filters.get("recordId").is_some() {"recordId".to_string()}
        else if self.filters.get("attester").is_some() {"attester".to_string()}
        else if self.filters.get("parentId").is_some() {"parentId".to_string()}
        else if self.filters.get("recipient").is_some() {"recipient".to_string()}
        else if self.filters.get("contextId").is_some() {"contextId".to_string()}
        else if self.filters.get("protocolPath").is_some() {"protocolPath".to_string()}
        else if self.filters.get("schema").is_some() {"schema".to_string()}
        else if self.filters.get("protocol").is_some() {"protocol".to_string()}
        else { self.filters.keys().collect::<Vec<&String>>()[0].to_string() }
    }
    pub fn match_filter(&self, indexes: &KeyValues) -> bool {
        for (property_name, filter_value) in self.get_filters() {
            if let Some(values) = indexes.get(property_name) {
                for value in values {
                    if !filter_value.filter(value) {
                        return false;
                    }
                }
            } else {return false;}
        }
        true
    }
}

#[derive(Clone, PartialEq)]
pub enum SortDirection {
  Descending = -1,
  Ascending = 1
}

pub struct QueryOptions {
  pub sort_property: String,
  pub sort_direction: Option<SortDirection>,
  pub limit: Option<usize>,
  pub cursor: Option<PaginationCursor>
}

impl QueryOptions {
    pub fn sort_direction(&self) -> &SortDirection {self.sort_direction.as_ref().unwrap_or(&SortDirection::Ascending)}
    pub fn new(
        sort_property: String,
        sort_direction: Option<SortDirection>,
        limit: Option<usize>,
        cursor: Option<PaginationCursor>
    ) -> QueryOptions {
        QueryOptions{sort_property, sort_direction, limit, cursor}
    }
}

#[derive(Clone, Serialize, Deserialize, Eq, PartialEq, PartialOrd)]
pub struct IndexKey {
    pub index: String,
    pub item: Vec<u8>
}

impl Ord for IndexKey {
    fn cmp(&self, other: &Self) -> Ordering {
        serde_json::to_string(&self).unwrap().cmp(&serde_json::to_string(other).unwrap())
    }
}

pub type PaginationCursor = IndexKey;

#[derive(Serialize, Deserialize, Debug, Clone, Eq, Hash, PartialEq)]
pub struct IndexedItem {
    pub item: Vec<u8>,
    pub indexes: KeyValues
}

pub struct Index {}
impl Index {
    fn p_name(name: &str) -> String {format!("__{}__", name)}

    pub fn clear(
        store: Box<&mut dyn KeyValueStore>
    ) -> Result<(), Error> {
        let index_lookup = store.partition(&INDEX_SUBLEVEL_NAME)?;
        let indexes = index_lookup.values()?.iter().map(|b| Ok(deserialize::<KeyValues>(b)?)).collect::<Result<Vec<KeyValues>, Error>>()?;
        index_lookup.clear()?;

        let mut keys: Vec<String> = vec![];
        for index in indexes {
            keys.append(&mut index.map().keys().map(|k| k.to_string()).collect::<Vec<String>>());
        }
        for key in keys {
            store.partition(&key)?.clear()?;
        }
        Ok(())
    }

    pub fn delete(store: Box<&mut dyn KeyValueStore>, value: &[u8]) -> Result<bool, Error> {
        let index_lookup = store.partition(INDEX_SUBLEVEL_NAME)?;
        if let Some(indexes) = index_lookup.get(value)? {
            index_lookup.delete(value)?;
            let indexes: KeyValues = deserialize(&indexes)?;
            for (index_name, index_values) in indexes.map().iter() {
                let index_partition = store.partition(&Self::p_name(index_name))?;
                for index_value in index_values {
                    let item_key = IndexKey{item: value.to_vec(), index: index_value.clone()};
                    index_partition.delete(&serialize(&item_key)?)?;
                }
            }
            return Ok(true);
        }
        Ok(false)
    }

    pub fn set(store: Box<&mut dyn KeyValueStore>, value: &[u8], indexes: KeyValues) -> Result<(), Error> {
        let item_value = serialize(&IndexedItem{item: value.to_vec(), indexes: indexes.clone()})?;
        for (index_name, index_values) in indexes.map.iter() {
            let index_partition = store.partition(&Self::p_name(index_name))?;
            for index_value in index_values {
                let item_key = IndexKey{item: value.to_vec(), index: index_value.clone()};
                index_partition.set(&serialize(&item_key)?, &item_value)?;
            }
        }
        store.partition(INDEX_SUBLEVEL_NAME)?.set(value, &serialize(&indexes)?)?;
        Ok(())
    }

    pub fn query<'a>(
        store: Box<&'a dyn KeyValueStore>,
        filter: Option<PropertyFilter>,
        query_options: &QueryOptions
    ) -> Result<Vec<IndexedItem>, Error> {
        let mut filter = filter;
        let sort_property = &query_options.sort_property;
        if filter.get(sort_property).is_none() {filter.insert_filter(sort_property, Filter::HasField);}
        let sort_direction = query_options.sort_direction();
        let mut results = if let Some(filter) = filter {
            Self::get_all_by_index(store.clone(), &filter.get_most_narrow_index())?.into_iter().filter(|item| {
                    filter.match_filter(&item.indexes)
            }).collect::<Vec<IndexedItem>>()
        } else {
            Self::get_all_by_index(store, &sort_property)?
        };

        Self::sort_indexed_items(&mut results, &sort_property, &sort_direction);
        Ok(Self::subslice_cursor_limit(&results, &query_options.cursor, &query_options.limit, &sort_direction))
    }

    fn get_all_by_index(
        store: Box<&dyn KeyValueStore>,
        index_name: &str
    ) -> Result<Vec<IndexedItem>, Error> {
        Ok(match store.get_partition(&Self::p_name(index_name)) {
            Some(index_partition) => {
                index_partition.values()?.into_iter().map(|b| {
                    Ok(deserialize::<IndexedItem>(&b)?)
                }).collect::<Result<Vec<IndexedItem>, Error>>()?
            },
            None => Vec::new()
        })
    }

    fn subslice_cursor_limit(
        items: &Vec<IndexedItem>,
        cursor: &Option<IndexKey>,
        limit: &Option<usize>,
        sort_direction: &SortDirection
    ) -> Vec<IndexedItem> {
        let start = if let Some(cursor) = cursor {
             let find_next_after_cursor_item = || {
                if let Some(index) = items.iter().position(|item| item.item == cursor.item) {
                    let mut index = index;
                    let increment = sort_direction.clone() as usize;
                    loop {
                        index += increment;
                        if let Some(item) = items.get(index) {
                            if item.item != cursor.item {
                                return Some(index);
                            }
                        } else { break; }
                    }
                }
                return None
            };
            find_next_after_cursor_item()
        } else { None }.unwrap_or(0);

        let end = if let Some(limit) = limit {
            std::cmp::min(start+limit, items.len())
        } else { items.len() };

        items[start..end].to_vec()
    }

    fn sort_indexed_items(
        items: &mut Vec<IndexedItem>,
        sort_property: &str,
        sort_direction: &SortDirection
    ) -> () {
        items.sort_by(|a, b| {
            let a = format!("{}{}", serde_json::to_string(a.indexes.get(sort_property).unwrap()).unwrap(), serde_json::to_string(&a.item).unwrap());
            let b = format!("{}{}", serde_json::to_string(b.indexes.get(sort_property).unwrap()).unwrap(), serde_json::to_string(&b.item).unwrap());
            if sort_direction == &SortDirection::Ascending {
                a.cmp(&b)
            } else {
                b.cmp(&a)
            }
        });
    }
}
