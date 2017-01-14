//! Base types for dealing with resource records.
pub use self::a::{A, AType};
pub use self::aaaa::{AAAA, AAAAType};
pub use self::cname::{CNAME, CNAMEType};
use std::fmt;
use super::names::Name;

/// Helper macro for the resource record `Type`.
#[macro_export]
macro_rules! resource_type {
    ($typename:ident, $name:expr, $value:expr) => (
        #[derive(Debug,Clone,Copy)]
        #[allow(missing_docs)]
        pub struct $typename;

        impl Type for $typename {
            fn name(&self) -> &str {
                $name
            }
            fn value(&self) -> u16 {
                $value
            }
        }
    );
}

/// Helper macro for the resource record definitions.
#[macro_export]
macro_rules! resource_record_impl {
    ($rrname:ident, $typename:ident, $name:expr, $value:expr, $data:ty) => (
        resource_type!($typename, $name, $value);
        impl ResourceRecord for $rrname {
            type RRType = $typename;
            type DataType = $data;
            fn name(&self) -> &Name {
                &self.name
            }
            fn rr_type(&self) -> $typename {
                $typename {}
            }
            fn rr_class(&self) -> &Class {
                &self.class
            }
            fn ttl(&self) -> i32 {
                self.ttl
            }

            fn data(&self) -> &$data {
                &self.data
            }
        }
    );
}

/// A more complete macro than `resource_record_impl!` offers:
#[macro_export]
macro_rules! resource_record {
    (pub struct $rrname:ident {
        $typename:ident, $name:expr, $value:expr,
        data: $data:ty
    }) => (
        pub struct $rrname {
            name: Name,
            class: Class,
            ttl: i32,
            data: $data
        }
        resource_record_impl!($rrname, $typename, $name, $value, $data);
    );
}

mod a;
mod aaaa;
mod cname;

/// A `Type` field indicates the structure and content of a resource record.
pub trait Type {
    /// A short name for the type.
    ///
    /// # Examples
    /// - A
    /// - NS
    /// - SOA
    /// - MX
    /// - CNAME
    fn name(&self) -> &str;
    /// The 16-bit value uniquely assigned to this type.
    fn value(&self) -> u16;
}

/// Enum for valid `class` values from DNS resource records.
#[derive(Debug,PartialEq,Clone,Copy)]
pub enum Class {
    /// The "Internet" class.
    IN,
}

/// A resource record associates a `Name` within a `Class` with `Type` dependent data.
pub trait ResourceRecord {
    /// Each `ResourceRecord` must have a distinct `Type`.
    type RRType: Type;
    /// The type of data stored by this record.
    type DataType;

    /// Returns the `Name` this record applies to.
    fn name(&self) -> &Name;
    /// Returns the `Type` identifier for this record.
    fn rr_type(&self) -> Self::RRType;
    /// Returns the `Class` this record applies to.
    fn rr_class(&self) -> &Class;
    /// Returns the "time to live" for this data.
    ///
    /// DNS systems are expected to cache data for this length of time.
    fn ttl(&self) -> i32;

    /// Returns the data that this record provides.
    ///
    /// # Examples
    /// For the `A` record, this would be the IPv4 address. A `CNAME` record would contain the
    /// canonical name that is referred to by this record's name.
    fn data(&self) -> &Self::DataType;
}

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
