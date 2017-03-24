//! Base types for dealing with resource records.

use super::{Class, Type, class_from, type_from, ResourceRecord};
use names::{Name, parse_name};

use nom::{be_u8, be_u16, be_u32, be_i32, IResult, ErrorKind};
use nom::IResult::*;
use std::net::{Ipv4Addr, Ipv6Addr};

named!(pub parse_class<&[u8], Class>,
    map!(be_u16, class_from)
);

named!(pub parse_type(&[u8]) -> Type,
    map!(be_u16, type_from)
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
pub fn parse_record<'a>(i: &'a [u8], data: &'a [u8]) -> IResult<&'a [u8], ResourceRecord> {
    let (output, name) = try_parse!(i, apply!(parse_name, data));
    let (output, rtype) = try_parse!(output, parse_type);
    match rtype {
        Type::A => parse_a(output, name),
        Type::AAAA => parse_aaaa(output, name),
        Type::CNAME => parse_cname(output, data, name),
        Type::SOA => parse_soa(output, data, name),
        Type::PTR => parse_ptr(output, data, name),
        Type::OPT => parse_opt(output, name),
        Type::MX => parse_mx(output, data, name),
        Type::NS => parse_ns(output, data, name),
        Type::TXT => parse_txt(output, name),
        Type::Unknown { value: a } => parse_unknown(output, name, a),
    }
}

fn parse_unknown<'a>(i: &'a [u8], name: Name, rtype: u16) -> IResult<&'a [u8], ResourceRecord> {
    parse_body_unknown(i).map(|args: (Class, i32, &[u8])| {
        let mut vec = Vec::with_capacity(args.2.len());
        vec.extend(args.2.iter().cloned());
        ResourceRecord::Unknown {
            name: name,
            rtype: rtype,
            class: args.0,
            ttl: args.1,
            data: vec,
        }
    })
}

named!(parse_body_unknown<&[u8], (Class, i32, &[u8])>,
    do_parse!(
        class: parse_class >>
        ttl: be_i32 >>
        length: be_u16 >>
        data: take!( length ) >>
        ((class, ttl, data))
    )
);

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
        class: parse_class >>
        ttl: be_i32 >>
        length: add_return_error!(ErrorKind::Custom(403), tag!( b"\x00\x04" )) >>
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
        class: parse_class >>
        ttl: be_i32 >>
        length: add_return_error!(ErrorKind::Custom(405), tag!( "\x00\x10" )) >>
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

fn parse_cname<'a>(i: &'a [u8], data: &'a [u8], name: Name) -> IResult<&'a [u8], ResourceRecord> {
    do_parse!(i,
        class: parse_class >>
        ttl: be_i32 >>
        rr: length_value!(be_u16,
            do_parse!(
                cname: apply!(parse_name, data) >>
                (ResourceRecord::CNAME {
                    name: name,
                    class: class,
                    ttl: ttl,
                    cname: cname,
                })
            )
        ) >>
        (rr)
    )
}

fn parse_ptr<'a>(i: &'a [u8], data: &'a [u8], name: Name) -> IResult<&'a [u8], ResourceRecord> {
    do_parse!(i,
        class: parse_class >>
        ttl: be_i32 >>
        rr: length_value!(be_u16,
            do_parse!(
                ptrname: apply!(parse_name, data) >>
                (ResourceRecord::PTR {
                    name: name,
                    class: class,
                    ttl: ttl,
                    ptrname: ptrname,
                })
            )
        ) >>
        (rr)
    )
}

fn parse_ns<'a>(i: &'a [u8], data: &'a [u8], name: Name) -> IResult<&'a [u8], ResourceRecord> {
    do_parse!(i,
        class: parse_class >>
        ttl: be_i32 >>
        rr: length_value!(be_u16,
            do_parse!(
                ns_name: apply!(parse_name, data) >>
                (ResourceRecord::NS {
                    name: name,
                    class: class,
                    ttl: ttl,
                    ns_name: ns_name,
                })
            )
        ) >>
        (rr)
    )
}

fn parse_soa<'a>(i: &'a [u8], data: &'a [u8], name: Name) -> IResult<&'a [u8], ResourceRecord> {
    do_parse!(i,
        class: parse_class >>
        ttl: be_i32 >>
        soa: length_value!(be_u16,
            do_parse!(
                mname: apply!(parse_name, data) >>
                rname: apply!(parse_name, data) >>
                serial: be_u32 >>
                refresh: be_u32 >>
                retry: be_u32 >>
                expire: be_u32 >>
                minimum: be_u32 >>
                (ResourceRecord::SOA {
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
            )
        ) >>
        (soa)
    )
}

fn parse_opt<'a>(i: &'a [u8], name: Name) -> IResult<&'a [u8], ResourceRecord> {
    if !name.is_root() {
        return Error(ErrorKind::Custom(410));
    }
    do_parse!(i,
        payload_size: be_u16 >>
        rcode: be_u8 >>
        version: be_u8 >>
        flags: be_u16 >>
        length: be_u16 >>
        data: take!(length) >>
        (ResourceRecord::OPT {
                payload_size: payload_size,
                extended_rcode: rcode,
                version: version,
                dnssec_ok: (flags & 0b1000_0000_0000_0000) != 0,
                data: {
                    let mut vec = Vec::with_capacity(length as usize);
                    vec.extend(data.iter().cloned());
                    vec
                },
            })
    )
}

fn parse_mx<'a>(i: &'a [u8], data: &'a [u8], name: Name) -> IResult<&'a [u8], ResourceRecord> {
    do_parse!(i,
        class: parse_class >>
        ttl: be_i32 >>
        rr: length_value!(be_u16,
            do_parse!(
                preference: be_u16 >>
                exchange: apply!(parse_name, data) >>
                (ResourceRecord::MX {
                    name: name,
                    class: class,
                    ttl: ttl,
                    preference: preference,
                    exchange: exchange,
                })
            )
        ) >>
        (rr)
    )
}

fn parse_txt<'a>(i: &'a [u8], name: Name) -> IResult<&'a [u8], ResourceRecord> {
    do_parse!(i,
        class: parse_class >>
        ttl: be_i32 >>
        length: be_u16 >>
        bytes: flat_map!( take!( length ), many1!( parse_char_string ) ) >>
        (ResourceRecord::TXT {
            name: name,
            class: class,
            ttl: ttl,
            data: bytes,
        })
    )
}

named!(parse_char_string<&[u8], String>,
    do_parse!(
        length: be_u8 >>
        s: take_str!( length ) >>
        (String::from(s))
    )
);

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
