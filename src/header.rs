use nom::be_u16;

/// Query operation types
#[derive(Debug,Clone,Copy,PartialEq)]
pub enum Opcode {
    /// Standard query
    Query,
    /// Inverse query
    InverseQuery,
    /// Status request
    Status,
    /// Placeholder for values unknown to this library.
    Unknown {
        /// The actual byte value of the (unrecognized) opcode.
        value: u8
     }
}

/// Response types
#[derive(Debug,Clone,Copy,PartialEq)]
pub enum Rcode {
    /// No error condition.
    NoError,
    /// The name server was unable to interpret the query.
    FormatError,
    /// There was a problem with the name server.
    ServerFailure,
    /// (Authoritative server only) - signifies the domain name does not exist.
    NameError,
    /// The requested query is not implemented.
    NotImplemented,
    /// The query was refused for policy reasons.
    Refused,
    /// Placeholder for values unknown to this library.
    Unknown { value: u8 },
}

/// Header for resource record queries and responses
#[derive(Debug,Clone,Copy,PartialEq)]
pub struct Header {
    /// A 16 bit identifier assigned by the program.
    pub id: u16,
    /// Specifies whether this message is a query (`false`) or response (`true`).
    pub qr: bool,
    /// The type of query
    pub opcode: Opcode,
    /// Whether the response is authoritative
    pub authoritative: bool,
    /// Whether the response is truncated
    pub truncated: bool,
    /// Whether recursion is desired
    pub recursion_desired: bool,
    /// Whether recursion is available
    pub recursion_available: bool,
    /// The response code
    pub rcode: Rcode,
    /// The number of entries in the question section.
    pub question_count: u16,
    /// The number of entries in the resource records section.
    pub answer_count: u16,
    /// The number of entries in the authority records section.
    pub ns_count: u16,
    /// The number of entries in the additional records section.
    pub additional_count: u16,
}

impl Header {
    /// Create a `Header` for a query
    pub fn query(id: u16, opcode: Opcode, recursion_desired: bool, questions: u16) -> Header {
        Header {
            id: id,
            qr: false,
            opcode: opcode,
            authoritative: false,
            truncated: false,
            recursion_desired: recursion_desired,
            recursion_available: false,
            rcode: Rcode::NoError,
            question_count: questions,
            answer_count: 0,
            ns_count: 0,
            additional_count: 0,
        }
    }

    /// Create a `Header` for a response
    pub fn response(query: Header, recursion_available: bool) -> Header {
        Header {
            id: query.id,
            qr: true,
            opcode: query.opcode,
            authoritative: false,
            truncated: false,
            recursion_desired: query.recursion_desired,
            recursion_available: recursion_available,
            rcode: Rcode::NoError,
            question_count: query.question_count,
            answer_count: 0,
            ns_count: 0,
            additional_count: 0,
        }
    }

    /// Creates a copy of the header, with the `answer_count` field modified.
    pub fn answers(&self, count: u16) -> Header {
        Header {
            id: self.id,
            qr: self.qr,
            opcode: self.opcode,
            authoritative: self.authoritative,
            truncated: self.truncated,
            recursion_desired: self.recursion_desired,
            recursion_available: self.recursion_available,
            rcode: self.rcode,
            question_count: self.question_count,
            answer_count: count,
            ns_count: self.ns_count,
            additional_count: self.additional_count,
        }
    }

    /// Creates a copy of the header, with the `ns_count` field modified.
    pub fn authorities(&self, count: u16) -> Header {
        Header {
            id: self.id,
            qr: self.qr,
            opcode: self.opcode,
            authoritative: self.authoritative,
            truncated: self.truncated,
            recursion_desired: self.recursion_desired,
            recursion_available: self.recursion_available,
            rcode: self.rcode,
            question_count: self.question_count,
            answer_count: self.answer_count,
            ns_count: count,
            additional_count: self.additional_count,
        }
    }

    /// Creates a copy of the header, with the `additional_count` field modified.
    pub fn additional(&self, count: u16) -> Header {
        Header {
            id: self.id,
            qr: self.qr,
            opcode: self.opcode,
            authoritative: self.authoritative,
            truncated: self.truncated,
            recursion_desired: self.recursion_desired,
            recursion_available: self.recursion_available,
            rcode: self.rcode,
            question_count: self.question_count,
            answer_count: self.answer_count,
            ns_count: self.ns_count,
            additional_count: count,
        }
    }
}

//                                 1  1  1  1  1  1
//   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      ID                       |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    QDCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ANCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    NSCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ARCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

fn opcode_from(bits: u8) -> Opcode {
    match bits {
        0 => Opcode::Query,
        1 => Opcode::InverseQuery,
        2 => Opcode::Status,
        x @ _ => Opcode::Unknown { value: x },
    }
}
fn rcode_from(bits: u8) -> Rcode {
    match bits {
        0 => Rcode::NoError,
        1 => Rcode::FormatError,
        2 => Rcode::ServerFailure,
        3 => Rcode::NameError,
        4 => Rcode::NotImplemented,
        5 => Rcode::Refused,
        x @ _ => Rcode::Unknown { value: x },
    }
}

named!(header_flags<&[u8], (bool, Opcode, bool, bool, bool, bool, Rcode)>,
bits!(do_parse!(
     qr:     take_bits!( u8, 1 ) >>
     opcode: map!(take_bits!( u8, 4 ), opcode_from) >>
     aa:     take_bits!( u8, 1 ) >>
     tc:     take_bits!( u8, 1 ) >>
     rd:     take_bits!( u8, 1 ) >>
     ra:     take_bits!( u8, 1 ) >>
     zero:   take_bits!( u8, 3 ) >>
     rcode:  map!(take_bits!( u8, 4 ), rcode_from) >>
     (((qr == 1), opcode, (aa == 1), (tc == 1), (rd == 1), (ra == 1), rcode))
)));

named!(pub parse_header<&[u8], Header>,
do_parse!(
    id:          be_u16 >>
    flags: header_flags >>
    qdcount:     be_u16 >>
    ancount:     be_u16 >>
    nscount:     be_u16 >>
    arcount:     be_u16 >>
    (Header {
        id: id,
        qr: flags.0,
        opcode: flags.1,
        authoritative: flags.2,
        truncated: flags.3,
        recursion_desired: flags.4,
        recursion_available: flags.5,
        rcode: flags.6,
        question_count: qdcount,
        answer_count: ancount,
        ns_count: nscount,
        additional_count: arcount
    })
));

#[cfg(test)]
mod tests {
    use nom::IResult::Done;
    use super::*;

    fn query_1() -> Header {
        Header::query(2, Opcode::Query, true, 1)
    }
    fn response_1() -> Header {
        Header::response(query_1(), true).answers(1)
    }

    #[test]
    fn parse_query_1_header() {
        let data = include_bytes!("../assets/captures/dns_1_query.bin");
        assert_eq!(parse_header(&data[0..12]), Done(&b""[..], query_1()));
    }

    #[test]
    fn parse_response_1_header() {
        let data = include_bytes!("../assets/captures/dns_1_response.bin");
        assert_eq!(parse_header(&data[0..12]), Done(&b""[..], response_1()));
    }

    fn query_2() -> Header {
        Header::query(3, Opcode::Query, true, 1)
    }
    fn response_2() -> Header {
        Header::response(query_2(), true).answers(1)
    }

    #[test]
    fn parse_query_2_header() {
        let data = include_bytes!("../assets/captures/dns_2_query.bin");
        assert_eq!(parse_header(&data[0..12]), Done(&b""[..], query_2()));
    }

    #[test]
    fn parse_response_2_header() {
        let data = include_bytes!("../assets/captures/dns_2_response.bin");
        assert_eq!(parse_header(&data[0..12]), Done(&b""[..], response_2()));
    }

    fn query_3() -> Header {
        Header::query(0xda64, Opcode::Query, true, 1)
    }
    fn response_3() -> Header {
        Header::response(query_3(), true)
            .answers(2)
            .authorities(1)
    }

    #[test]
    fn parse_query_3_header() {
        let data = include_bytes!("../assets/captures/dns_3_query.bin");
        assert_eq!(parse_header(&data[0..12]), Done(&b""[..], query_3()));
    }

    #[test]
    fn parse_response_3_header() {
        let data = include_bytes!("../assets/captures/dns_3_response.bin");
        assert_eq!(parse_header(&data[0..12]), Done(&b""[..], response_3()));
    }

    fn query_4() -> Header {
        Header::query(0x60ff, Opcode::Query, true, 1).additional(1)
    }
    fn response_4() -> Header {
        Header::response(query_4(), true)
            .answers(13)
            .additional(1)
    }

    #[test]
    fn parse_query_4_header() {
        let data = include_bytes!("../assets/captures/dns_4_query.bin");
        assert_eq!(parse_header(&data[0..12]), Done(&b""[..], query_4()));
    }

    #[test]
    fn parse_response_4_header() {
        let data = include_bytes!("../assets/captures/dns_4_response.bin");
        assert_eq!(parse_header(&data[0..12]), Done(&b""[..], response_4()));
    }
}
