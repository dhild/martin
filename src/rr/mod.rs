//! Base types for dealing with resource records.

use names::Name;

use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

mod parser;
pub use self::parser::*;

/// A `Type` field indicates the structure and content of a resource record.
#[derive(Debug,PartialEq,Clone,Copy)]
pub enum Type {
    /// The `A` resource type, holding an IPv4 host address resource record.
    A,
    /// The `A` resource type, holding an IPv6 host address resource record.
    AAAA,
    /// The `CNAME` resource type, holding the canonical name for an alias.
    CNAME,
    /// The `SOA` resource type, marks the start of a zone of authority.
    SOA,
    /// The `OPT` pseudo-RR type, adding additional EDNS(0) information to a request / response.
    OPT,
    /// The `MX` resource type, holding mail exchange information.
    MX,
    /// The `NS` resource type, holding an authoritative name server.
    NS,
    /// The `TXT` resource type, holding text strings.
    TXT,
    /// Indicates that the type is not known to this parser.
    Unknown {
        /// The value of the unknown type
        value: u16,
    },
}

/// Enum for valid `class` values from DNS resource records.
#[derive(Debug,PartialEq,Clone,Copy)]
pub enum Class {
    /// The "Internet" class.
    Internet,
    /// The "CHAOS" class.
    Chaos,
    /// The "Hesoid" class.
    Hesoid,
    /// An unknown class value.
    Unknown {
        /// The value of the unknown type
        value: u16,
    },
}

/// A resource record associates a `Name` within a `Class` with `Type` dependent data.
#[derive(Debug,PartialEq,Clone)]
pub enum ResourceRecord {
    /// An IPv4 host address resource record.
    A {
        /// The `Name` this record applies to.
        name: Name,
        /// The `Class` this record applies to.
        class: Class,
        /// The "time to live" for this data, in seconds.
        ttl: i32,
        /// The IPv4 host address.
        addr: Ipv4Addr,
    },
    /// An IPv6 host address resource record.
    AAAA {
        /// The `Name` this record applies to.
        name: Name,
        /// The `Class` this record applies to.
        class: Class,
        /// The "time to live" for this data, in seconds.
        ttl: i32,
        /// The IPv6 host address.
        addr: Ipv6Addr,
    },
    /// The canonical name for an alias.
    CNAME {
        /// The `Name` this record applies to.
        name: Name,
        /// The `Class` this record applies to.
        class: Class,
        /// The "time to live" for this data, in seconds.
        ttl: i32,
        /// The canonical name for the alias referred to in `name`.
        cname: Name,
    },
    /// The start of a zone of authority.
    SOA {
        /// The `Name` this record applies to.
        name: Name,
        /// The `Class` this record applies to.
        class: Class,
        /// The "time to live" for this data, in seconds.
        ttl: i32,
        /// The <domain-name> of the name server that was the original or primary source of data
        /// for this zone.
        mname: Name,
        /// A <domain-name> which specifies the mailbox of the person responsible for this zone.
        rname: Name,
        /// The unsigned 32 bit version number of the original copy of the zone.
        ///
        ///  Zone transfers preserve this value. This value wraps and should be compared using
        /// sequence space arithmetic.
        serial: u32,
        /// A 32 bit time interval before the zone should be refreshed.
        refresh: u32,
        /// A 32 bit time interval that should elapse before a failed refresh should be retried.
        retry: u32,
        /// A 32 bit time value that specifies the upper limit on the time interval that can elapse
        /// before the zone is no longer authoritative.
        expire: u32,
        /// The unsigned 32 bit minimum TTL field that should be exported with any RR from this
        /// zone.
        minimum: u32,
    },
    /// Mail Exchange information.
    MX {
        /// The `Name` this record applies to.
        name: Name,
        /// The `Class` this record applies to.
        class: Class,
        /// The "time to live" for this data, in seconds.
        ttl: i32,
        /// The preference given to this RR - lower values are preferred.
        preference: u16,
        /// A host willing to act as a mail exchange for the owner name.
        exchange: Name,
    },
    /// An authoritative name server.
    NS {
        /// The `Name` this record applies to.
        name: Name,
        /// The `Class` this record applies to.
        class: Class,
        /// The "time to live" for this data, in seconds.
        ttl: i32,
        /// A host which should be authoritative for the specified class and domain.
        ns_name: Name,
    },
    /// A pseudo-record containing additional EDNS(0) information.
    OPT {
        /// The requestor's UDP payload size.
        payload_size: u16,
        /// An extended response code.
        extended_rcode: u8,
        /// The specification version supported.
        version: u8,
        /// The `DNSSEC OK` bit.
        dnssec_ok: bool,
        /// Additional data in the form of attribute, value pairs.
        data: Vec<u8>,
    },
    /// Text string record information.
    TXT {
        /// The `Name` this record applies to.
        name: Name,
        /// The `Class` this record applies to.
        class: Class,
        /// The "time to live" for this data, in seconds.
        ttl: i32,
        /// One or more character strings.
        data: Vec<String>,
    },
    /// A yet-unknown type of resource record.
    Unknown {
        /// The `Name` this record applies to.
        name: Name,
        /// The type code for this unknown data.
        rtype: u16,
        /// The `Class` this record applies to.
        class: Class,
        /// The "time to live" for this data, in seconds.
        ttl: i32,
        /// The data contained by the unknown record type.
        data: Vec<u8>,
    },
}

fn class_from(value: u16) -> Class {
    match value {
        1u16 => Class::Internet,
        3u16 => Class::Chaos,
        4u16 => Class::Hesoid,
        _ => Class::Unknown { value: value },
    }
}

pub fn type_from(value: u16) -> Type {
    match value {
        1u16 => Type::A,
        2u16 => Type::NS,
        5u16 => Type::CNAME,
        6u16 => Type::SOA,
        15u16 => Type::MX,
        16u16 => Type::TXT,
        28u16 => Type::AAAA,
        41u16 => Type::OPT,
        _ => Type::Unknown { value: value },
    }
}

impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Class::Internet => write!(f, "IN"),
            Class::Chaos => write!(f, "CH"),
            Class::Hesoid => write!(f, "HS"),
            Class::Unknown { value: x } => write!(f, "0x{:x}", x),
        }
    }
}

impl fmt::Display for Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Type::A => write!(f, "A"),
            Type::AAAA => write!(f, "AAAA"),
            Type::CNAME => write!(f, "CNAME"),
            Type::SOA => write!(f, "SOA"),
            Type::OPT => write!(f, "OPT"),
            Type::MX => write!(f, "MX"),
            Type::NS => write!(f, "NS"),
            Type::TXT => write!(f, "TXT"),
            Type::Unknown { value: x } => write!(f, "0x{:x}", x),
        }
    }
}
