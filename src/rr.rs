//! Base types for dealing with resource records.

use crate::names::Name;
use std::convert::From;
use std::fmt;
use std::fmt::{Display, Formatter};
use std::io::{Cursor, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use byteorder::{BigEndian, WriteBytesExt};

/// A `Type` field indicates the structure and content of a resource record.
#[derive(Debug, PartialEq, Clone, Copy)]
pub enum Type {
    /// The `A` resource type, holding an IPv4 host address resource record.
    A,
    /// The `A` resource type, holding an IPv6 host address resource record.
    AAAA,
    /// The `CNAME` resource type, holding the canonical name for an alias.
    CNAME,
    /// The `PTR` resource type, pointing to a canonical name. Does not trigger `CNAME` processing.
    PTR,
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
#[derive(Debug, PartialEq, Clone, Copy)]
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
#[derive(Debug, PartialEq, Clone)]
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
    /// Pointer to a canonical name.
    PTR {
        /// The `Name` this record applies to.
        name: Name,
        /// The `Class` this record applies to.
        class: Class,
        /// The "time to live" for this data, in seconds.
        ttl: i32,
        /// The canonical name pointed to in `name`.
        ptrname: Name,
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
        rtype: Type,
        /// The `Class` this record applies to.
        class: Class,
        /// The "time to live" for this data, in seconds.
        ttl: i32,
        /// The data contained by the unknown record type.
        data: Vec<u8>,
    },
}

impl ResourceRecord {
    pub fn name(&self) -> Option<&Name> {
        match self {
            ResourceRecord::A { name, .. } => Some(name),
            ResourceRecord::AAAA { name, .. } => Some(name),
            ResourceRecord::CNAME { name, .. } => Some(name),
            ResourceRecord::SOA { name, .. } => Some(name),
            ResourceRecord::PTR { name, .. } => Some(name),
            ResourceRecord::MX { name, .. } => Some(name),
            ResourceRecord::NS { name, .. } => Some(name),
            ResourceRecord::OPT { .. } => None,
            ResourceRecord::TXT { name, .. } => Some(name),
            ResourceRecord::Unknown { name, .. } => Some(name),
        }
    }
    pub fn rtype(&self) -> Type {
        match self {
            ResourceRecord::A {..} => Type::A,
            ResourceRecord::AAAA {..} => Type::AAAA,
            ResourceRecord::CNAME {..} => Type::CNAME,
            ResourceRecord::SOA {..} => Type::SOA,
            ResourceRecord::PTR {..} => Type::PTR,
            ResourceRecord::MX {..} => Type::MX,
            ResourceRecord::NS {..} => Type::NS,
            ResourceRecord::OPT {..} => Type::OPT,
            ResourceRecord::TXT {..} => Type::TXT,
            ResourceRecord::Unknown {rtype, ..} => *rtype,
        }
    }
    pub fn ttl(&self) -> Option<i32> {
        match self {
            ResourceRecord::A { ttl, .. } => Some(*ttl),
            ResourceRecord::AAAA { ttl, .. } => Some(*ttl),
            ResourceRecord::CNAME { ttl, .. } => Some(*ttl),
            ResourceRecord::SOA { ttl, .. } => Some(*ttl),
            ResourceRecord::PTR { ttl, .. } => Some(*ttl),
            ResourceRecord::MX { ttl, .. } => Some(*ttl),
            ResourceRecord::NS { ttl, .. } => Some(*ttl),
            ResourceRecord::OPT { .. } => None,
            ResourceRecord::TXT { ttl, .. } => Some(*ttl),
            ResourceRecord::Unknown { ttl, .. } => Some(*ttl),
        }
    }
}

impl Display for ResourceRecord {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ResourceRecord::A { name, class, ttl,  addr } => write!(f, "{name} {} {class} {ttl} {addr}", Type::A),
            ResourceRecord::AAAA { name, class, ttl, addr } => write!(f, "{name} {} {class} {ttl} {addr}", Type::AAAA),
            ResourceRecord::CNAME { name, class, ttl, cname } => write!(f, "{name} {} {class} {ttl} {cname}", Type::CNAME),
            ResourceRecord::SOA { name, class, ttl, .. } => write!(f, "{name} {} {class} {ttl}", Type::SOA),
            ResourceRecord::PTR { name, class, ttl, ptrname } => write!(f, "{name} {} {class} {ttl} {ptrname}", Type::PTR),
            ResourceRecord::MX { name, class, ttl,preference, exchange } => write!(f, "{name} {} {class} {ttl} {preference} {exchange}", Type::MX),
            ResourceRecord::NS { name, class, ttl, ns_name } => write!(f, "{name} {} {class} {ttl} {ns_name}", Type::NS),
            ResourceRecord::OPT { .. } => write!(f, ". {}", Type::OPT),
            ResourceRecord::TXT { name, class, ttl, data } => write!(f, "{name} {} {class} {ttl} {data:?}", Type::TXT),
            ResourceRecord::Unknown { name, rtype, class, ttl, data } => write!(f, "{name} {rtype} {class} {ttl} {data:?}"),
        }
    }
}

impl From<u16> for Class {
    fn from(value: u16) -> Class {
        match value {
            1u16 => Class::Internet,
            3u16 => Class::Chaos,
            4u16 => Class::Hesoid,
            _ => Class::Unknown { value },
        }
    }
}

impl From<Class> for u16 {
    fn from(value: Class) -> u16 {
        match value {
            Class::Internet => 1u16,
            Class::Chaos => 3u16,
            Class::Hesoid => 4u16,
            Class::Unknown { value: x } => x,
        }
    }
}

impl From<u16> for Type {
    fn from(value: u16) -> Type {
        match value {
            1u16 => Type::A,
            2u16 => Type::NS,
            5u16 => Type::CNAME,
            6u16 => Type::SOA,
            12u16 => Type::PTR,
            15u16 => Type::MX,
            16u16 => Type::TXT,
            28u16 => Type::AAAA,
            41u16 => Type::OPT,
            _ => Type::Unknown { value },
        }
    }
}

impl From<Type> for u16 {
    fn from(value: Type) -> u16 {
        match value {
            Type::A => 1u16,
            Type::NS => 2u16,
            Type::CNAME => 5u16,
            Type::SOA => 6u16,
            Type::PTR => 12u16,
            Type::MX => 15u16,
            Type::TXT => 16u16,
            Type::AAAA => 28u16,
            Type::OPT => 41u16,
            Type::Unknown { value: x } => x,
        }
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
            Type::PTR => write!(f, "PTR"),
            Type::OPT => write!(f, "OPT"),
            Type::MX => write!(f, "MX"),
            Type::NS => write!(f, "NS"),
            Type::TXT => write!(f, "TXT"),
            Type::Unknown { value: x } => write!(f, "0x{:x}", x),
        }
    }
}

impl ResourceRecord {
    pub fn write_to<T>(&self, cursor: &mut Cursor<T>) -> std::io::Result<()>
        where Cursor<T>: Write
    {
        match *self {
            ResourceRecord::OPT { payload_size, extended_rcode, version, dnssec_ok, ref data } => {
                cursor.write_u8(0)?;
                cursor.write_u16::<BigEndian>(Type::OPT.into())?;
                cursor.write_u16::<BigEndian>(payload_size)?;
                cursor.write_u8(extended_rcode)?;
                cursor.write_u8(version)?;
                let flags = if dnssec_ok { 0b1000_0000_0000_0000 } else { 0 };
                cursor.write_u16::<BigEndian>(flags)?;
                cursor.write_u16::<BigEndian>(data.len() as u16)?;
                cursor.write_all(data)
            }
            ResourceRecord::A { ref name, class, ttl, ref addr } => {
                write_data(name, Type::A, class, ttl, &addr.octets(), cursor)
            }
            ResourceRecord::AAAA { ref name, class, ttl, ref addr } => {
                write_data(name, Type::AAAA, class, ttl, &addr.octets(), cursor)
            }
            ResourceRecord::CNAME { ref name, class, ttl, ref cname } => {
                name.write_to(cursor)?;
                cursor.write_u16::<BigEndian>(Type::CNAME.into())?;
                cursor.write_u16::<BigEndian>(class.into())?;
                cursor.write_i32::<BigEndian>(ttl)?;

                let start = cursor.position();
                cursor.write_u16::<BigEndian>(0)?;
                cname.write_to(cursor)?;
                let end = cursor.position();
                cursor.set_position(start);
                cursor.write_u16::<BigEndian>((end - start) as u16)?;
                cursor.set_position(end);
                Ok(())
            }
            ResourceRecord::SOA {
                ref name,
                class,
                ttl,
                ref mname,
                ref rname,
                serial,
                refresh,
                retry,
                expire,
                minimum
            } => {
                name.write_to(cursor)?;
                cursor.write_u16::<BigEndian>(Type::SOA.into())?;
                cursor.write_u16::<BigEndian>(class.into())?;
                cursor.write_i32::<BigEndian>(ttl)?;

                let start = cursor.position();
                cursor.write_u16::<BigEndian>(0)?;

                mname.write_to(cursor)?;
                rname.write_to(cursor)?;
                cursor.write_u32::<BigEndian>(serial)?;
                cursor.write_u32::<BigEndian>(refresh)?;
                cursor.write_u32::<BigEndian>(retry)?;
                cursor.write_u32::<BigEndian>(expire)?;
                cursor.write_u32::<BigEndian>(minimum)?;

                let end = cursor.position();
                cursor.set_position(start);
                cursor.write_u16::<BigEndian>((end - start) as u16)?;
                cursor.set_position(end);
                Ok(())
            }
            ResourceRecord::PTR { ref name, class, ttl, .. } => {
                write_data(name, Type::PTR, class, ttl, &[], cursor)
            }
            ResourceRecord::MX { ref name, class, ttl, preference, ref exchange } => {
                name.write_to(cursor)?;
                cursor.write_u16::<BigEndian>(Type::MX.into())?;
                cursor.write_u16::<BigEndian>(class.into())?;
                cursor.write_i32::<BigEndian>(ttl)?;

                let start = cursor.position();
                cursor.write_u16::<BigEndian>(0)?;

                cursor.write_u16::<BigEndian>(preference)?;
                exchange.write_to(cursor)?;

                let end = cursor.position();
                cursor.set_position(start);
                cursor.write_u16::<BigEndian>((end - start) as u16)?;
                cursor.set_position(end);
                Ok(())
            }
            ResourceRecord::NS { ref name, class, ttl, ref ns_name } => {
                name.write_to(cursor)?;
                cursor.write_u16::<BigEndian>(Type::NS.into())?;
                cursor.write_u16::<BigEndian>(class.into())?;
                cursor.write_i32::<BigEndian>(ttl)?;

                let start = cursor.position();
                cursor.write_u16::<BigEndian>(0)?;

                ns_name.write_to(cursor)?;

                let end = cursor.position();
                cursor.set_position(start);
                cursor.write_u16::<BigEndian>((end - start) as u16)?;
                cursor.set_position(end);
                Ok(())
            }
            ResourceRecord::TXT { ref name, class, ttl, .. } => {
                write_data(name, Type::TXT, class, ttl, &[], cursor)
            }
            ResourceRecord::Unknown { ref name, rtype, class, ttl, ref data } => {
                write_data(name, rtype, class, ttl, data, cursor)
            }
        }
    }
}

fn write_data<T>(name: &Name, rtype: Type, rclass: Class, ttl: i32, data: &[u8], cursor: &mut Cursor<T>) -> std::io::Result<()> where Cursor<T>: Write {
    name.write_to(cursor)?;
    cursor.write_u16::<BigEndian>(rtype.into())?;
    cursor.write_u16::<BigEndian>(rclass.into())?;
    cursor.write_i32::<BigEndian>(ttl)?;
    cursor.write_u16::<BigEndian>(data.len() as u16)?;
    cursor.write_all(data)?;
    Ok(())
}