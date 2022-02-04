use std::fmt::{Display, Formatter};
use crate::header::{Header, Opcode, Rcode};
use crate::question::{QType, Question};
use crate::rr::{Class, ResourceRecord, Type};
use std::io::{Cursor, Write};
use nom::bytes::complete::{tag, take_while_m_n};
use nom::combinator::{eof, fail};
use nom::IResult;
use nom::multi::{count, length_data};
use nom::number::complete::{be_u128, be_u16, be_u32, be_u8};
use nom::sequence::tuple;
use crate::names::{Name};

/// Describes a DNS query or response.
#[derive(Debug, Clone, PartialEq)]
pub struct Message {
    pub header: Header,
    /// The question(s) for the name server
    pub questions: Vec<Question>,
    /// Resource records answering the question
    pub answers: Vec<ResourceRecord>,
    /// Resource records pointing toward an authority
    pub authorities: Vec<ResourceRecord>,
    /// Resource records holding additional information
    pub additionals: Vec<ResourceRecord>,
}

impl Message {
    /// A 16 bit identifier assigned by the program.
    pub fn id(&self) -> u16 {
        self.header.id
    }
    /// Returns `true` if this message is a query.
    pub fn is_query(&self) -> bool {
        !self.is_response()
    }
    /// Returns `true` if this message is a response.
    pub fn is_response(&self) -> bool {
        self.header.qr
    }
    /// The type of query
    pub fn opcode(&self) -> Opcode {
        self.header.opcode
    }
    /// Whether the response is authoritative
    pub fn authoritative(&self) -> bool {
        self.header.authoritative
    }
    /// Whether the response is truncated
    pub fn truncated(&self) -> bool {
        self.header.truncated
    }
    /// Whether recursion is desired
    pub fn recursion_desired(&self) -> bool {
        self.header.recursion_desired
    }
    /// Whether recursion is available
    pub fn recursion_available(&self) -> bool {
        self.header.recursion_available
    }
    /// The response code
    pub fn rcode(&self) -> Rcode {
        self.header.rcode
    }

    /// Creates a `Message` for sending a standard query
    pub fn query(id: u16, recursion_desired: bool, question: Question) -> Message {
        Message {
            header: Header::query(id, Opcode::Query, recursion_desired, 1),
            questions: vec![question],
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }

    /// Creates a `Message` for sending a response
    pub fn response(query: Message, recursion_available: bool) -> Message {
        Message {
            header: Header::response(query.header, recursion_available),
            questions: query.questions,
            answers: Vec::new(),
            authorities: Vec::new(),
            additionals: Vec::new(),
        }
    }
}

impl Display for Message {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        write!(f, "Message {} ({} {}) {} {} {} {} {:?}\n",
               self.id(),
               if self.is_query() { "Q" } else { "R" },
               match self.opcode() {
                   Opcode::Query => "Q",
                   Opcode::InverseQuery => "I",
                   Opcode::Status => "S",
                   Opcode::Unknown { .. } => " ",
               },
               if self.authoritative() { "A" } else { " " },
               if self.truncated() { "T" } else { " " },
               if self.recursion_desired() { "r" } else { " " },
               if self.recursion_available() { "R" } else { " " },
               self.rcode(),
        )?;
        for q in self.questions.iter() {
            write!(f, "    Question ({:?}): {}\n", q.qtype, q.qname)?;
        }
        for rr in self.authorities.iter() {
            write!(f, "    Authority: {rr}\n")?;
        }
        for rr in self.answers.iter() {
            write!(f, "    Answer: {rr}\n")?;
        }
        for rr in self.additionals.iter() {
            write!(f, "    Additional: {rr}\n")?;
        }
        Ok(())
    }
}

impl Message {
    /// Encodes a `Message` into a stream of bytes.
    pub fn encode(&self) -> Vec<u8> {
        let mut cursor = Cursor::new(Vec::new());
        self.write_to(&mut cursor).unwrap();
        cursor.into_inner()
    }

    /// Writes a `Message` into a stream of bytes.
    pub fn write_to<T>(&self, cursor: &mut Cursor<T>) -> std::io::Result<()> where Cursor<T>: Write {
        self.header.write_to(cursor).unwrap();

        for q in self.questions.iter() {
            q.write_to(cursor)?;
        }
        for rr in self.answers.iter().chain(self.authorities.iter()).chain(self.additionals.iter()) {
            rr.write_to(cursor)?;
        }
        Ok(())
    }

    pub fn decode(buf: &[u8]) -> Result<Message, nom::Err<nom::error::Error<Vec<u8>>>> {
        let parser = |i| -> IResult<&[u8], Message> {
            let (i, msg) = parse_message(i)?;
            let (i, _) = eof(i)?;
            Ok((i, msg))
        };
        parser(buf).map(|(_, msg)| msg).map_err(|e| e.to_owned())
    }
}

fn parse_message(buf: &[u8]) -> IResult<&[u8], Message> {
    let (i, header) = parse_header(buf)?;
    let (i, questions) = count(parse_question(buf), header.question_count as usize)(i)?;
    let (i, answers) = count(parse_rr(buf), header.answer_count as usize)(i)?;
    let (i, authorities) = count(parse_rr(buf), header.ns_count as usize)(i)?;
    let (i, additionals) = count(parse_rr(buf), header.additional_count as usize)(i)?;
    Ok((i, Message {
        header,
        questions,
        answers,
        authorities,
        additionals,
    }))
}

fn parse_header(i: &[u8]) -> IResult<&[u8], Header> {
    let (i, id) = be_u16(i)?;
    let (i, flags) = be_u16(i)?;
    let (i, question_count) = be_u16(i)?;
    let (i, answer_count) = be_u16(i)?;
    let (i, ns_count) = be_u16(i)?;
    let (i, additional_count) = be_u16(i)?;

    Ok((i, Header {
        id,
        qr: (flags & 0b1000_0000_0000_0000) != 0,
        opcode: Opcode::from(((flags & 0b0111_1000_0000_0000) >> 11) as u8),
        authoritative: (flags & 0b0000_0100_0000_0000) != 0,
        truncated: (flags & 0b0000_0010_0000_0000) != 0,
        recursion_desired: (flags & 0b0000_0001_0000_0000) != 0,
        recursion_available: (flags & 0b0000_0000_1000_0000) != 0,
        rcode: Rcode::from((flags & 0b0000_0000_0000_1111) as u8),
        question_count,
        answer_count,
        ns_count,
        additional_count,
    }))
}

fn parse_question<'a>(data: &'a [u8]) -> impl Fn(&'a [u8]) -> IResult<&'a [u8], Question> {
    |i| -> IResult<&[u8], Question> {
        let (i, qname) = parse_name(data)(i)?;
        let (i, qtype) = be_u16(i)?;
        let (i, qclass) = be_u16(i)?;
        Ok((i, Question { qname, qtype: QType::from(qtype), qclass: Class::from(qclass) }))
    }
}

fn parse_name<'a>(data: &'a [u8]) -> impl Fn(&'a [u8]) -> IResult<&'a [u8], Name> {
    |i| -> IResult<&[u8], Name> {
        let (i, length) = be_u8(i)?;
        if length == 0 {
            return Ok((i, Name { name: vec![0] }));
        }
        match length & 0xC0 {
            0 => {
                let (i, first) = take_while_m_n(1, length as usize, |item: u8| item.is_ascii_alphanumeric())(i)?;
                let rem = length as usize - first.len();
                let (i, second) = take_while_m_n(rem, rem, |item: u8| item.is_ascii_alphanumeric() || item as char == '-')(i)?;
                let (i, next) = parse_name(data)(i)?;
                let mut name = Vec::with_capacity(1 + length as usize + next.name.len());
                name.push(length);
                name.extend_from_slice(first);
                name.extend_from_slice(second);
                name.extend(next.name);
                Ok((i, Name { name }))
            }
            0xC0 => {
                let (i, offset_low) = be_u8(i)?;
                let offset = (length as usize & 0x3F) << 8 | offset_low as usize;
                // Refuse to look ahead in the data; compression is expected to only work in reverse
                if offset > (data.len() - i.len()) {
                    fail(i)
                } else {
                    let (_, name) = parse_name(data)(&data[offset..])?;
                    Ok((i, name))
                }
            }
            // Catch-all because the match arms complain otherwise
            // Technically, they are valid u8 values; but they aren't valid outputs of the AND operation.
            0x40 | 0x80 | _ => {
                // Reserved bits
                fail(i)
            }
        }
    }
}

fn parse_class(i: &[u8]) -> IResult<&[u8], Class> {
    let (i, c) = be_u16(i)?;
    Ok((i, Class::from(c)))
}

fn parse_type(i: &[u8]) -> IResult<&[u8], Type> {
    let (i, t) = be_u16(i)?;
    Ok((i, Type::from(t)))
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

fn parse_rr<'a>(data: &'a [u8]) -> impl Fn(&'a [u8]) -> IResult<&'a [u8], ResourceRecord> {
    |i| -> IResult<&[u8], ResourceRecord> {
        let (i, (name, rtype, class, ttl)) = tuple((parse_name(data), parse_type, parse_class, be_u32))(i)?;
        match rtype {
            Type::A => {
                let (i, (_, addr)) = tuple((tag([0u8, 4u8]), be_u32))(i)?;
                Ok((i, ResourceRecord::A { name, class, ttl: ttl as i32, addr: addr.into() }))
            }
            Type::AAAA => {
                let (i, (_, addr)) = tuple((tag([0u8, 16u8]), be_u128))(i)?;
                Ok((i, ResourceRecord::AAAA { name, class, ttl: ttl as i32, addr: addr.into() }))
            }
            // TODO: Parse all known types
            _ => {
                let (i, data) = length_data(be_u16)(i)?;
                Ok((i, ResourceRecord::Unknown { name, rtype, class, ttl: ttl as i32, data: data.into() }))
            }
        }
    }
}
