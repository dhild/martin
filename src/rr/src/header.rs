use byteorder::{BigEndian, WriteBytesExt};
use errors::{be_u16, ParseError};
use nom::IResult;
use std::convert::From;
use std::io;
use std::io::Write;

/// Query operation type
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
        /// The unrecognized opcode.
        value: u8,
    },
}

/// Response status codes
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
    Unknown {
        /// The unrecognized response code.
        value: u8,
    },
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

    fn flags_to_u16(&self) -> u16 {
        let opcode: u8 = self.opcode.into();
        let rcode: u8 = self.rcode.into();
        let mut res = (rcode as u16) | ((opcode as u16) << 11);
        if self.qr {
            res |= 0b1000_0000_0000_0000;
        }
        if self.authoritative {
            res |= 0b0000_0100_0000_0000;
        }
        if self.truncated {
            res |= 0b0000_0010_0000_0000;
        }
        if self.recursion_desired {
            res |= 0b0000_0001_0000_0000;
        }
        if self.recursion_available {
            res |= 0b0000_0000_1000_0000;
        }
        res
    }
}

pub fn write_header(header: &Header, writer: &mut Write) -> io::Result<()> {
    writer.write_u16::<BigEndian>(header.id)?;
    writer.write_u16::<BigEndian>(header.flags_to_u16())?;
    writer.write_u16::<BigEndian>(header.question_count)?;
    writer.write_u16::<BigEndian>(header.answer_count)?;
    writer.write_u16::<BigEndian>(header.ns_count)?;
    writer.write_u16::<BigEndian>(header.additional_count)?;
    Ok(())
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

impl From<u8> for Opcode {
    fn from(bits: u8) -> Opcode {
        match bits {
            0 => Opcode::Query,
            1 => Opcode::InverseQuery,
            2 => Opcode::Status,
            x => Opcode::Unknown { value: x },
        }
    }
}

impl From<Opcode> for u8 {
    fn from(opcode: Opcode) -> u8 {
        match opcode {
            Opcode::Query => 0,
            Opcode::InverseQuery => 1,
            Opcode::Status => 2,
            Opcode::Unknown { value: x } => x,
        }
    }
}

impl From<u8> for Rcode {
    fn from(bits: u8) -> Rcode {
        match bits {
            0 => Rcode::NoError,
            1 => Rcode::FormatError,
            2 => Rcode::ServerFailure,
            3 => Rcode::NameError,
            4 => Rcode::NotImplemented,
            5 => Rcode::Refused,
            x => Rcode::Unknown { value: x },
        }
    }
}

impl From<Rcode> for u8 {
    fn from(rcode: Rcode) -> u8 {
        match rcode {
            Rcode::NoError => 0,
            Rcode::FormatError => 1,
            Rcode::ServerFailure => 2,
            Rcode::NameError => 3,
            Rcode::NotImplemented => 4,
            Rcode::Refused => 5,
            Rcode::Unknown { value: x } => x,
        }
    }
}

pub fn parse_header(i: &[u8]) -> IResult<&[u8], Header, ParseError> {
    let (i, id) = try_parse!(i, be_u16);
    let (i, flags) = try_parse!(i, be_u16);
    let (i, qdcount) = try_parse!(i, be_u16);
    let (i, ancount) = try_parse!(i, be_u16);
    let (i, nscount) = try_parse!(i, be_u16);
    let (i, arcount) = try_parse!(i, be_u16);
    let header = Header {
        id: id,
        qr: (flags & 0b1000_0000_0000_0000) != 0,
        opcode: Opcode::from(((flags & 0b0111_1000_0000_0000) >> 11) as u8),
        authoritative: (flags & 0b0000_0100_0000_0000) != 0,
        truncated: (flags & 0b0000_0010_0000_0000) != 0,
        recursion_desired: (flags & 0b0000_0001_0000_0000) != 0,
        recursion_available: (flags & 0b0000_0000_1000_0000) != 0,
        rcode: Rcode::from((flags & 0b0000_0000_0000_1111) as u8),
        question_count: qdcount,
        answer_count: ancount,
        ns_count: nscount,
        additional_count: arcount,
    };
    IResult::Done(i, header)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom::IResult::Done;

    fn query_1() -> Header {
        Header::query(2, Opcode::Query, true, 1)
    }
    fn response_1() -> Header {
        let mut h = Header::response(query_1(), true);
        h.answer_count = 1;
        h
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
        let mut h = Header::response(query_2(), true);
        h.answer_count = 1;
        h
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
        let mut h = Header::response(query_3(), true);
        h.answer_count = 2;
        h.ns_count = 1;
        h
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
        let mut h = Header::query(0x60ff, Opcode::Query, true, 1);
        h.additional_count = 1;
        h
    }
    fn response_4() -> Header {
        let mut h = Header::response(query_4(), true);
        h.answer_count = 13;
        h.additional_count = 1;
        h
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
