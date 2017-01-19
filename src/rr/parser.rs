//! Base types for dealing with resource records.

use names::{Name, parse_name};

use nom::{be_u8, be_u16, be_u32, be_i32, IResult, Needed, ErrorKind};
use nom::IResult::*;
use std::net::{Ipv4Addr, Ipv6Addr};
use super::{Class, Type, class_from, type_from, ResourceRecord};

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
pub fn parse_record<'a>(data: &'a [u8], i: &'a [u8]) -> IResult<&'a [u8], ResourceRecord> {
    let name = parse_name(data, i);
    if let Done(output, name) = name {
        let rtype = parse_type(output);
        if let Done(output, rtype) = rtype {
            return match rtype {
                Type::A => parse_a(output, name),
                Type::AAAA => parse_aaaa(output, name),
                Type::CNAME => parse_cname(data, output, name),
                Type::SOA => parse_soa(data, output, name),
                Type::OPT => parse_opt(output, name),
                Type::MX => parse_mx(data, output, name),
                Type::NS => parse_ns(data, output, name),
                Type::TXT => parse_txt(output, name),
                Type::Unknown { value: a } => parse_unknown(output, name, a),
            };
        };
        match rtype {
            Done(_, _) => unreachable!(),
            Error(e) => return Error(error_node_position!(ErrorKind::Custom(401), i, e)),
            Incomplete(e) => return Incomplete(e),
        }
    };
    match name {
        Done(_, _) => unreachable!(),
        Error(e) => return Error(e),
        Incomplete(e) => return Incomplete(e),
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

fn parse_cname<'a>(data: &'a [u8], i: &'a [u8], name: Name) -> IResult<&'a [u8], ResourceRecord> {
    parse_simple_name(data, i).map(|args:  (Class, i32, Name)| {
        ResourceRecord::CNAME {
            name: name,
            class: args.0,
            ttl: args.1,
            cname: args.2,
        }
    })
}

fn parse_simple_name<'a>(data: &'a [u8], i: &'a [u8]) -> IResult<&'a [u8], (Class, i32, Name)> {
    let (output, (class, ttl, length)) = try_parse!(i, parse_simple_body);
    match parse_name(data, output) {
        Done(_, second_name) => Done(&output[length..], (class, ttl, second_name)),
        Error(e) => Error(e),
        Incomplete(e) => Incomplete(e),
    }
}

named!(parse_simple_body<&[u8], (Class, i32, usize)>,
    do_parse!(
        class: parse_class >>
        ttl: be_i32 >>
        length: be_u16 >>
        ((class, ttl, length as usize))
    )
);

fn parse_ns<'a>(data: &'a [u8], i: &'a [u8], name: Name) -> IResult<&'a [u8], ResourceRecord> {
    parse_simple_name(data, i).map(|args:  (Class, i32, Name)| {
        ResourceRecord::NS {
            name: name,
            class: args.0,
            ttl: args.1,
            ns_name: args.2,
        }
    })
}

fn parse_soa<'a>(data: &'a [u8], i: &'a [u8], name: Name) -> IResult<&'a [u8], ResourceRecord> {
    let (output, (class, ttl, length)) = try_parse!(i, parse_body_soa_1);
    if output.len() < length {
        let size = length - output.len();
        return Incomplete(Needed::Size(size));
    };
    let mname = parse_name(data, output);
    if let Done(o2, mname) = mname {
        let rname = parse_name(data, o2);
        if let Done(o3, rname) = rname {
            let args = parse_body_soa_2(o3);
            if let Done(_, args) = args {
                return Done(&output[length..], ResourceRecord::SOA {
                    name: name,
                    class: class,
                    ttl: ttl,
                    mname: mname,
                    rname: rname,
                    serial: args.0,
                    refresh: args.1,
                    retry: args.2,
                    expire: args.3,
                    minimum: args.4
                });
            };
            match args {
                Done(_, _) => unreachable!(),
                Error(e) => return Error(e),
                Incomplete(e) => return Incomplete(e),
            }
        };
        match rname {
            Done(_, _) => unreachable!(),
            Error(e) => return Error(e),
            Incomplete(e) => return Incomplete(e),
        }
    };
    match mname {
        Done(_, _) => unreachable!(),
        Error(e) => return Error(e),
        Incomplete(e) => return Incomplete(e),
    }
}

named!(parse_body_soa_1<&[u8], (Class, i32, usize)>,
    do_parse!(
        class: parse_class >>
        ttl: be_i32 >>
        length: be_u16 >>
        ((class, ttl, length as usize))
    )
);

named!(parse_body_soa_2<&[u8], (u32, u32, u32, u32, u32)>,
    do_parse!(
        serial: be_u32 >>
        refresh: be_u32 >>
        retry: be_u32 >>
        expire: be_u32 >>
        minimum: be_u32 >>
        ((serial, refresh, retry, expire, minimum))
    )
);

fn parse_opt<'a>(i: &'a [u8], name: Name) -> IResult<&'a [u8], ResourceRecord> {
    if !name.is_root() {
        return Error(ErrorKind::Custom(410));
    }
    parse_body_opt(i).map(|args: (u16, u8, u8, u16, &[u8])| {
        let mut vec = Vec::with_capacity(args.4.len());
        vec.extend(args.4.iter().cloned());
        ResourceRecord::OPT {
            payload_size: args.0,
            extended_rcode: args.1,
            version: args.2,
            dnssec_ok: (args.3 & 0b1000_0000_0000_0000) != 0,
            data: vec,
        }
    })
}

named!(parse_body_opt<&[u8], (u16, u8, u8, u16, &[u8])>,
    do_parse!(
        payload_size: be_u16 >>
        rcode: be_u8 >>
        version: be_u8 >>
        flags: be_u16 >>
        length: be_u16 >>
        data: take!(length) >>
        ((payload_size, rcode, version, flags, data))
    )
);

fn parse_mx<'a>(data: &'a [u8], i: &'a [u8], name: Name) -> IResult<&'a [u8], ResourceRecord> {
    let (output, (class, ttl, length, preference)) = try_parse!(i, parse_body_mx);
    match parse_name(data, output) {
        Done(_, exchange) => Done(&output[length..], ResourceRecord::MX {
            name: name,
            class: class,
            ttl: ttl,
            preference: preference,
            exchange: exchange,
        }),
        Error(e) => Error(e),
        Incomplete(e) => Incomplete(e),
    }
}

named!(parse_body_mx<&[u8], (Class, i32, usize, u16)>,
    do_parse!(
        class: parse_class >>
        ttl: be_i32 >>
        length: be_u16 >>
        preference: be_u16 >>
        ((class, ttl, (length - 2) as usize, preference))
    )
);

fn parse_txt<'a>(i: &'a [u8], name: Name) -> IResult<&'a [u8], ResourceRecord> {
    let (output, (class, ttl, data)) = try_parse!(i, parse_body_txt);
    Done(output, ResourceRecord::TXT {
        name: name,
        class: class,
        ttl: ttl,
        data: data,
    })
}

named!(parse_body_txt<&[u8], (Class, i32, Vec<String>)>,
    do_parse!(
        class: parse_class >>
        ttl: be_i32 >>
        length: be_u16 >>
        bytes: flat_map!( take!( length ), many1!( parse_char_string ) ) >>
        ((class, ttl, bytes))
    )
);

named!(parse_char_string<&[u8], String>,
    do_parse!(
        length: be_u8 >>
        s: take_str!( length ) >>
        (String::from(s))
    )
);

#[cfg(test)]
mod tests {
    use nom::IResult::Done;
    use std::net::Ipv4Addr;
    use super::*;
    use rr::{Type, Class, ResourceRecord};

    #[test]
    fn parse_type_bytes() {
        let a = b"\x00\x01abcd";
        let aaaa = b"\x00\x1cabcd";
        let cname = b"\x00\x05abcd";
        let md_deprecated = b"\x00\x03abcd";

        assert_eq!(parse_type(&a[..]), Done(&b"abcd"[..], Type::A));
        assert_eq!(parse_type(&aaaa[..]), Done(&b"abcd"[..], Type::AAAA));
        assert_eq!(parse_type(&cname[..]), Done(&b"abcd"[..], Type::CNAME));
        assert_eq!(parse_type(&md_deprecated[..]), Done(&b"abcd"[..], Type::Unknown { value: 3 }));
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
        assert_eq!(parse_class(&b[..]), Done(&b"abcd"[..], Class::Unknown { value: 2 }));
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
