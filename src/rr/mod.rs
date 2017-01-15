//! Base types for dealing with resource records.
mod a;
mod aaaa;
mod cname;

pub use self::a::A;
pub use self::aaaa::AAAA;
pub use self::cname::CNAME;
use std::fmt;
use super::names::Name;

/// A `Type` field indicates the structure and content of a resource record.
#[derive(Debug,PartialEq,Clone,Copy)]
pub enum Type {
    /// The `A` resource type, holding an IPv4 host address resource record
    A,
    /// The `A` resource type, holding an IPv6 host address resource record
    AAAA,
    /// The `CNAME` resource type, holding the canonical name for an alias
    CNAME
}

/// Enum for valid `class` values from DNS resource records.
#[derive(Debug,PartialEq,Clone,Copy)]
pub enum Class {
    /// The "Internet" class.
    IN,
}

/// A resource record associates a `Name` within a `Class` with `Type` dependent data.
pub trait ResourceRecord {
    /// Returns the `Name` this record applies to.
    fn name(&self) -> &Name;
    /// Returns the `Type` identifier for this record.
    fn rr_type(&self) -> Type;
    /// Returns the `Class` this record applies to.
    fn rr_class(&self) -> Class;
    /// Returns the "time to live" for this data.
    ///
    /// DNS systems are expected to cache data for this length of time.
    fn ttl(&self) -> i32;
}

named!(pub parse_class<&[u8], Class>,
    value!(Class::IN, tag!(b"IN"))
);

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Class::IN => write!(f, "IN"),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
