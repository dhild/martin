//! Base types for dealing with resource records.

use names::{Name, parse_name};

use nom::{be_u8, be_u16, be_i32, IResult, ErrorKind};
use std::fmt;
use std::net::{Ipv4Addr, Ipv6Addr};

/// A `Type` field indicates the structure and content of a resource record.
#[derive(Debug,PartialEq,Clone,Copy)]
pub enum Type {
    /// The `A` resource type, holding an IPv4 host address resource record
    A,
    /// The `A` resource type, holding an IPv6 host address resource record
    AAAA,
    /// The `CNAME` resource type, holding the canonical name for an alias
    CNAME,
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
}

named!(pub parse_class<&[u8], Class>,
    switch!(be_u16,
        1u16 => value!(Class::Internet) |
        3u16 => value!(Class::Chaos) |
        4u16 => value!(Class::Hesoid)
    )
);

pub fn type_from(value: u16) -> Option<Type> {
    match value {
        1u16 => Some(Type::A),
        28u16 => Some(Type::AAAA),
        5u16 => Some(Type::CNAME),
        _ => None,
    }
}

named!(pub parse_type<&[u8], Type>,
    map_opt!(be_u16, type_from)
);

//                                 1  1  1  1  1  1
//   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                                               |
// /                                               /
// /                      NAME                     /
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      TYPE                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                     CLASS                     |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      TTL                      |
// |                                               |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                   RDLENGTH                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
// /                     RDATA                     /
// /                                               /
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

/// Parses a byte stream into a `ResourceRecord`
pub fn parse_record<'a>(data: &'a [u8], i: &'a [u8]) -> IResult<&'a [u8], ResourceRecord> {
    let name = parse_name(data, i);
    if let IResult::Done(output, name) = name {
        let rtype = parse_type(output);
        if let IResult::Done(_, rtype) = rtype {
            match rtype {
                Type::A => return parse_a(output, name),
                Type::AAAA => return parse_aaaa(output, name),
                _ => return IResult::Error(ErrorKind::Custom(1)),
            }
        };
        match rtype {
            IResult::Done(_, _) => unreachable!(),
            IResult::Error(e) => return IResult::Error(e),
            IResult::Incomplete(e) => return IResult::Incomplete(e),
        }
    };
    match name {
        IResult::Done(_, _) => unreachable!(),
        IResult::Error(e) => return IResult::Error(e),
        IResult::Incomplete(e) => return IResult::Incomplete(e),
    }
}

fn parse_a<'a>(i: &'a [u8], name: Name) -> IResult<&'a [u8], ResourceRecord> {
    parse_body_a(i).map(|args: (Class, i32, Ipv4Addr)| {
        ResourceRecord::A {
            name: name,
            class: args.0,
            ttl: args.1,
            addr: args.2,
        }
    })
}

named!(parse_body_a<&[u8], (Class, i32, Ipv4Addr)>,
    do_parse!(
        rtype: tag!( b"\x00\x01" ) >>
        class: parse_class >>
        ttl: be_i32 >>
        length: tag!( b"\x00\x04" ) >>
        a: be_u8 >>
        b: be_u8 >>
        c: be_u8 >>
        d: be_u8 >>
        ((class, ttl, Ipv4Addr::new(a, b, c, d)))
    )
);

fn parse_aaaa<'a>(i: &'a [u8], name: Name) -> IResult<&'a [u8], ResourceRecord> {
    parse_body_aaaa(i).map(|args: (Class, i32, Ipv6Addr)| {
        ResourceRecord::AAAA {
            name: name,
            class: args.0,
            ttl: args.1,
            addr: args.2,
        }
    })
}

named!(parse_body_aaaa<&[u8], (Class, i32, Ipv6Addr)>,
    do_parse!(
        rtype: tag!( b"\x00\x1c" ) >>
        class: parse_class >>
        ttl: be_i32 >>
        length: tag!( "\x00\x10" ) >>
        a: be_u16 >>
        b: be_u16 >>
        c: be_u16 >>
        d: be_u16 >>
        e: be_u16 >>
        f: be_u16 >>
        g: be_u16 >>
        h: be_u16 >>
        ((class, ttl, Ipv6Addr::new(a, b, c, d, e, f, g, h)))
    )
);


impl fmt::Display for Class {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Class::Internet => write!(f, "IN"),
            Class::Chaos => write!(f, "CH"),
            Class::Hesoid => write!(f, "HS"),
        }
    }
}

#[cfg(test)]
mod tests {
    use nom::ErrorKind;
    use nom::IResult::{Done, Error};
    use std::net::Ipv4Addr;
    use super::*;

    #[test]
    fn parse_type_bytes() {
        let a = b"\x00\x01abcd";
        let aaaa = b"\x00\x1cabcd";
        let cname = b"\x00\x05abcd";
        let md_deprecated = b"\x00\x03abcd";

        assert_eq!(parse_type(&a[..]), Done(&b"abcd"[..], Type::A));
        assert_eq!(parse_type(&aaaa[..]), Done(&b"abcd"[..], Type::AAAA));
        assert_eq!(parse_type(&cname[..]), Done(&b"abcd"[..], Type::CNAME));
        assert_eq!(parse_type(&md_deprecated[..]),
            Error(error_node_position!(ErrorKind::MapOpt, &b"\x00\x03abcd"[..],
                                       error_position!(ErrorKind::Tag, &b"\x00\x03abcd"[..]))));
    }

    #[test]
    fn parse_class_bytes() {
        let a = b"\x00\x01abcd";
        let b = b"\x00\x02abcd";
        let c = b"\x00\x03abcd";
        let d = b"\x00\x04abcd";

        assert_eq!(parse_class(&a[..]), Done(&b"abcd"[..], Class::Internet));
        assert_eq!(parse_class(&c[..]), Done(&b"abcd"[..], Class::Chaos));
        assert_eq!(parse_class(&d[..]), Done(&b"abcd"[..], Class::Hesoid));
        assert_eq!(parse_class(&b[..]),
            Error(error_node_position!(ErrorKind::Switch, &b"\x00\x02abcd"[..],
                                       error_position!(ErrorKind::Tag, &b"\x00\x02abcd"[..]))));
    }

    #[test]
    fn parse_a_record() {
        let src = b"\x03FOO\x03BAR\x00\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x7f\x00\x00\x01";
        assert_eq!(parse_record(&src[..], &src[..]),
                    Done(&b""[..], ResourceRecord::A {
                        name: "FOO.BAR.".parse().unwrap(),
                        class: Class::Internet,
                        ttl: 3600,
                        addr: Ipv4Addr::new(127, 0, 0, 1)
                    }));
    }

    #[test]
    fn parse_aaaa_record() {
        let src = b"\x03FOO\x03BAR\x00\x00\x1c\x00\x01\x00\x00\x0e\x10\x00\x10\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01";
        assert_eq!(parse_record(&src[..], &src[..]),
                    Done(&b""[..], ResourceRecord::AAAA {
                        name: "FOO.BAR.".parse().unwrap(),
                        class: Class::Internet,
                        ttl: 3600,
                        addr: "::1".parse().unwrap()
                    }));
    }
}
