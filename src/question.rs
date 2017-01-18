use nom::{be_u16, IResult};
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
    match parse_name(data, i) {
        IResult::Done(output, name) => {
            parse_fields(output).map(|args: (QType, Class)| {
                Question {
                    qname: name,
                    qtype: args.0,
                    qclass: args.1,
                }
            })
        }
        IResult::Error(e) => IResult::Error(e),
        IResult::Incomplete(e) => IResult::Incomplete(e),
    }
}

fn qtype_from(bits: u16) -> QType {
    match type_from(bits) {
        Type::Unknown {value: 252} => QType::ZoneTransfer,
        Type::Unknown {value: 253} => QType::MailRecords,
        Type::Unknown {value: 255} => QType::Any,
        t @ _ => QType::ByType(t),
    }
}

named!(parse_fields<&[u8], (QType, Class)>,
do_parse!(
    qtype:  map!(be_u16, qtype_from) >>
    qclass: parse_class >>
    ((qtype, qclass))
));
