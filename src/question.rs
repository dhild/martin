
use super::names::{Name, parse_name, NameParseError};
use super::rr::{Class, Type, parse_class, type_from};
use nom::{be_u16, IResult};
use nom::IResult::*;

/// The scope of query to execute.
#[derive(Debug,Clone,PartialEq,Copy)]
pub enum QType {
    /// The type of record being queried.
    ByType(Type),
    /// A query requesting all records for a name.
    Any,
}

/// Describes a DNS query.
#[derive(Debug,Clone,PartialEq)]
pub struct Question {
    qname: Name,
    qtype: QType,
    qclass: Class,
}

impl Question {
    /// Create a `Question`.
    pub fn new(qname: &str, qtype: QType, qclass: Class) -> Result<Question, NameParseError> {
        qname.parse().map(|name: Name| {
            Question {
                qname: name,
                qtype: qtype,
                qclass: qclass,
            }
        })
    }
}

pub fn parse_question<'a>(i: &'a [u8], data: &'a [u8]) -> IResult<&'a [u8], Question> {
    let (o1, name) = try_parse!(i, apply!(parse_name, data));
    let (o2, qtype) = try_parse!(o1, map!(be_u16, qtype_from));
    let (output, qclass) = try_parse!(o2, parse_class);
    Done(output,
         Question {
             qname: name,
             qtype: qtype,
             qclass: qclass,
         })
}

fn qtype_from(bits: u16) -> QType {
    match type_from(bits) {
        Type::Unknown { value: 255 } => QType::Any,
        t @ _ => QType::ByType(t),
    }
}
