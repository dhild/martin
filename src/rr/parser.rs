//! Base types for dealing with resource records.

// nom macro usage generates these warnings for a lot of parser functions in this file.
#![cfg_attr(feature = "dev", allow(needless_lifetimes))]

use errors::{be_u8, be_u16, be_u32, be_i32, take, ParseError};
use names::{Name, parse_name};

use nom::{IResult, ErrorKind, Needed};
use nom::IResult::*;
use rr::{Class, Type, ResourceRecord};
use std::net::{Ipv4Addr, Ipv6Addr};


pub fn parse_class(i: &[u8]) -> IResult<&[u8], Class, ParseError> {
    if i.len() < 2 {
        Incomplete(Needed::Size(2))
    } else {
        let x = Class::from(((i[0] as u16) << 8) + i[1] as u16);
        Done(&i[2..], x)
    }
}

pub fn parse_type(i: &[u8]) -> IResult<&[u8], Type, ParseError> {
    if i.len() < 2 {
        Incomplete(Needed::Size(2))
    } else {
        let x = Type::from(((i[0] as u16) << 8) + i[1] as u16);
        Done(&i[2..], x)
    }
}

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
pub fn parse_record<'a>(i: &'a [u8],
                        data: &'a [u8])
                        -> IResult<&'a [u8], ResourceRecord, ParseError> {
    let (i, name) = try_parse!(i, apply!(parse_name, data));
    let (i, rtype) = try_parse!(i, parse_type);
    match rtype {
        Type::A => parse_a(i, name),
        Type::AAAA => parse_aaaa(i, name),
        Type::CNAME => parse_cname(i, data, name),
        Type::SOA => parse_soa(i, data, name),
        Type::PTR => parse_ptr(i, data, name),
        Type::OPT => parse_opt(i, &name),
        Type::MX => parse_mx(i, data, name),
        Type::NS => parse_ns(i, data, name),
        Type::TXT => parse_txt(i, name),
        Type::Unknown { value: a } => parse_unknown(i, name, a),
    }
}

fn parse_parts(i: &[u8]) -> IResult<&[u8], (Class, i32, &[u8]), ParseError> {
    let (i, class) = try_parse!(i, parse_class);
    let (i, ttl) = try_parse!(i, be_i32);
    let (i, length) = try_parse!(i, be_u16);
    let (out, data) = try_parse!(i, apply!(take, length));
    Done(out, (class, ttl, data))
}

fn parse_parts_length(i: &[u8],
                      expected: usize,
                      t: Type)
                      -> IResult<&[u8], (Class, i32, &[u8]), ParseError> {
    let (i, class) = try_parse!(i, parse_class);
    let (i, ttl) = try_parse!(i, be_i32);
    let (i, length) = try_parse!(i, be_u16);
    if expected != length as usize {
        Error(ErrorKind::Custom(ParseError::InvalidRecordLength(t)))
    } else {
        let (i, data) = try_parse!(i, apply!(take, length));
        Done(i, (class, ttl, data))
    }
}

fn parse_unknown<'a>(i: &'a [u8],
                     name: Name,
                     rtype: u16)
                     -> IResult<&'a [u8], ResourceRecord, ParseError> {
    let (i, (class, ttl, bytes)) = try_parse!(i, parse_parts);
    Done(i,
         ResourceRecord::Unknown {
             name: name,
             rtype: rtype,
             class: class,
             ttl: ttl,
             data: bytes.to_vec(),
         })
}

fn parse_a<'a>(i: &'a [u8], name: Name) -> IResult<&'a [u8], ResourceRecord, ParseError> {
    let (i, (class, ttl, bytes)) = try_parse!(i, apply!(parse_parts_length, 4, Type::A));
    let addr = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
    Done(i,
         ResourceRecord::A {
             name: name,
             class: class,
             ttl: ttl,
             addr: addr,
         })
}

fn parse_aaaa<'a>(i: &'a [u8], name: Name) -> IResult<&'a [u8], ResourceRecord, ParseError> {
    let (i, (class, ttl, bytes)) = try_parse!(i, apply!(parse_parts_length, 16, Type::AAAA));
    let mut addr: [u8; 16] = Default::default();
    addr.copy_from_slice(&bytes[..16]);
    let addr = Ipv6Addr::from(addr);
    Done(i,
         ResourceRecord::AAAA {
             name: name,
             class: class,
             ttl: ttl,
             addr: addr,
         })
}

fn parse_cname<'a>(i: &'a [u8],
                   data: &'a [u8],
                   name: Name)
                   -> IResult<&'a [u8], ResourceRecord, ParseError> {
    let (out, (class, ttl, bytes)) = try_parse!(i, parse_parts);
    let (_, cname) = try_parse!(bytes, apply!(parse_name, data));
    Done(out,
         ResourceRecord::CNAME {
             name: name,
             class: class,
             ttl: ttl,
             cname: cname,
         })
}

fn parse_ptr<'a>(i: &'a [u8],
                 data: &[u8],
                 name: Name)
                 -> IResult<&'a [u8], ResourceRecord, ParseError> {
    let (i, (class, ttl, bytes)) = try_parse!(i, parse_parts);
    let (_, ptrname) = try_parse!(bytes, apply!(parse_name, data));
    Done(i,
         ResourceRecord::PTR {
             name: name,
             class: class,
             ttl: ttl,
             ptrname: ptrname,
         })
}

fn parse_ns<'a>(i: &'a [u8],
                data: &[u8],
                name: Name)
                -> IResult<&'a [u8], ResourceRecord, ParseError> {
    let (i, (class, ttl, bytes)) = try_parse!(i, parse_parts);
    let (_, ns_name) = try_parse!(bytes, apply!(parse_name, data));
    Done(i,
         ResourceRecord::NS {
             name: name,
             class: class,
             ttl: ttl,
             ns_name: ns_name,
         })
}

fn parse_soa<'a>(i: &'a [u8],
                 data: &[u8],
                 name: Name)
                 -> IResult<&'a [u8], ResourceRecord, ParseError> {
    let (i, (class, ttl, bytes)) = try_parse!(i, parse_parts);
    let (bytes, mname) = try_parse!(bytes, apply!(parse_name, data));
    let (bytes, rname) = try_parse!(bytes, apply!(parse_name, data));
    let (bytes, serial) = try_parse!(bytes, be_u32);
    let (bytes, refresh) = try_parse!(bytes, be_u32);
    let (bytes, retry) = try_parse!(bytes, be_u32);
    let (bytes, expire) = try_parse!(bytes, be_u32);
    let (_, minimum) = try_parse!(bytes, be_u32);
    Done(i,
         ResourceRecord::SOA {
             name: name,
             class: class,
             ttl: ttl,
             mname: mname,
             rname: rname,
             serial: serial,
             refresh: refresh,
             retry: retry,
             expire: expire,
             minimum: minimum,
         })
}

fn parse_opt<'a>(i: &'a [u8], name: &Name) -> IResult<&'a [u8], ResourceRecord, ParseError> {
    if !name.is_root() {
        return Error(ErrorKind::Custom(ParseError::OptNameNotRoot));
    }
    let (i, payload_size) = try_parse!(i, be_u16);
    let (i, rcode) = try_parse!(i, be_u8);
    let (i, version) = try_parse!(i, be_u8);
    let (i, flags) = try_parse!(i, be_u16);
    let (i, length) = try_parse!(i, be_u16);
    let (i, data) = try_parse!(i, apply!(take, length));
    Done(i,
         ResourceRecord::OPT {
             payload_size: payload_size,
             extended_rcode: rcode,
             version: version,
             dnssec_ok: (flags & 0b1000_0000_0000_0000) != 0,
             data: data.to_vec(),
         })
}

fn parse_mx<'a>(i: &'a [u8],
                data: &[u8],
                name: Name)
                -> IResult<&'a [u8], ResourceRecord, ParseError> {
    let (i, (class, ttl, bytes)) = try_parse!(i, parse_parts);
    let (bytes, preference) = try_parse!(bytes, be_u16);
    let (_, exchange) = try_parse!(bytes, apply!(parse_name, data));
    Done(i,
         ResourceRecord::MX {
             name: name,
             class: class,
             ttl: ttl,
             preference: preference,
             exchange: exchange,
         })
}

fn parse_txt<'a>(i: &'a [u8], name: Name) -> IResult<&'a [u8], ResourceRecord, ParseError> {
    let (i, (class, ttl, mut bytes)) = try_parse!(i, parse_parts);
    let mut data = Vec::new();
    while !bytes.is_empty() {
        let length = bytes[0] as usize;
        bytes = &bytes[1..];
        if bytes.len() < length {
            return Incomplete(Needed::Size(length));
        }
        match String::from_utf8(bytes[..length].to_vec()) {
            Ok(x) => data.push(x),
            Err(_) => return Error(ErrorKind::Custom(ParseError::TxtInvalidUtf8)),
        };
        bytes = &bytes[length..];
    }
    Done(i,
         ResourceRecord::TXT {
             name: name,
             class: class,
             ttl: ttl,
             data: data,
         })
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom::IResult::Done;
    use rr::{Type, Class, ResourceRecord};
    use std::net::Ipv4Addr;

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
                   Done(&b"abcd"[..], Type::Unknown { value: 3 }));
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
                   Done(&b"abcd"[..], Class::Unknown { value: 2 }));
    }

    #[test]
    fn parse_a_record() {
        let src = b"\x03FOO\x03BAR\x00\x00\x01\x00\x01\x00\x00\x0e\x10\x00\x04\x7f\x00\x00\x01";
        assert_eq!(parse_record(&src[..], &src[..]),
                   Done(&b""[..],
                        ResourceRecord::A {
                            name: "FOO.BAR.".parse().unwrap(),
                            class: Class::Internet,
                            ttl: 3600,
                            addr: Ipv4Addr::new(127, 0, 0, 1),
                        }));
    }

    #[test]
    fn parse_aaaa_record() {
        let a = b"\x03FOO\x03BAR\x00\x00\x1c\x00\x01\x00\x00\x0e\x10\x00\x10";
        let b = b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01";
        let src = [&a[..], &b[..]].concat();
        assert_eq!(parse_record(&src[..], &src[..]),
                   Done(&b""[..],
                        ResourceRecord::AAAA {
                            name: "FOO.BAR.".parse().unwrap(),
                            class: Class::Internet,
                            ttl: 3600,
                            addr: "::1".parse().unwrap(),
                        }));
    }
}
