use nom::{be_u16, IResult};
use nom::IResult::*;
use super::names::{Name, parse_name, NameParseError};
use super::rr::{Class, Type, parse_class, type_from};

/// A type of query
#[derive(Debug,Clone,PartialEq,Copy)]
pub enum QType {
    ByType(Type),
    ZoneTransfer,
    MailRecords,
    Any,
}

/// A type that describes a DNS query
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

pub fn parse_question<'a>(data: &'a [u8], i: &'a [u8]) -> IResult<&'a [u8], Question> {
    let (o1, name) = match parse_name(data, i) {
        Done(o, r) => (o, r),
        Error(e) => return Error(e),
        Incomplete(e) => return Incomplete(e),
    };
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
        Type::Unknown { value: 252 } => QType::ZoneTransfer,
        Type::Unknown { value: 253 } => QType::MailRecords,
        Type::Unknown { value: 255 } => QType::Any,
        t @ _ => QType::ByType(t),
    }
}
