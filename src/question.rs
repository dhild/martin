use errors::ParseError;
use names::{Name, parse_name, NameParseError};
use nom::{IResult, Needed};
use nom::IResult::*;
use rr::{Class, Type};
use std::convert::From;

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

pub fn parse_question<'a>(i: &'a [u8], data: &'a [u8]) -> IResult<&'a [u8], Question, ParseError> {
    let (i, name) = try_parse!(i, apply!(parse_name, data));
    if i.len() < 4 {
        return Incomplete(Needed::Size(4));
    }
    let qtype = QType::from(((i[0] as u16) << 8) + i[1] as u16);
    let qclass = Class::from(((i[2] as u16) << 8) + i[3] as u16);
    Done(&i[4..],
         Question {
             qname: name,
             qtype: qtype,
             qclass: qclass,
         })
}

impl From<u16> for QType {
    fn from(value: u16) -> QType {
        match Type::from(value) {
            Type::Unknown { value: 255 } => QType::Any,
            t => QType::ByType(t),
        }
    }
}
