pub struct QueryOptions {
  sortProperty: String,
  sortDirection: Option<SortDirection>,
  limit: Option<u32>,
  cursor: Option<PaginationCursor>
};

pub enum SortDirection {
  Descending, // = -1,
  Ascending, // = 1
}

//export type KeyValues = { [key:string]: string | number | boolean | string[] | number[] };
pub struct KeyValues {} //TODO: Looks like a hashmap???

export type EqualFilter = string | number | boolean;

export type OneOfFilter = EqualFilter[];

export type RangeValue = string | number;

/**
 * "greater than" or "greater than or equal to" range condition. `gt` and `gte` are mutually exclusive.
 */
export type GT = ({ gt: RangeValue } & { gte?: never }) | ({ gt?: never } & { gte: RangeValue });

/**
 * "less than" or "less than or equal to" range condition. `lt`, `lte` are mutually exclusive.
 */
export type LT = ({ lt: RangeValue } & { lte?: never }) | ({ lt?: never } & { lte: RangeValue });

/**
 * Ranger filter. 1 condition is required.
 */
export type RangeFilter = (GT | LT) & Partial<GT> & Partial<LT>;

export type StartsWithFilter = {
  startsWith: string;
};

export type FilterValue = EqualFilter | OneOfFilter | RangeFilter;

export type Filter = {
  [property: string]: FilterValue;
};

export type RangeCriterion = {
  /**
   * Inclusive starting date-time.
   */
  from?: string;

  /**
   * Inclusive end date-time.
   */
  to?: string;
};

export type PaginationCursor = {
  messageCid: string;
  value: string | number;
};
