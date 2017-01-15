use nom::{be_i32, IResult};
use super::names::{Name, parse_name};
use super::rr::{Class, parse_class};

/// A type that describes a DNS query
#[derive(Debug,Clone)]
pub struct Question {
    qname: Name,
    qtype: i32,
    qclass: Class,
}

pub fn parse_question<'a>(data: &'a [u8], i: &'a [u8]) -> IResult<&'a [u8], Question> {
    match parse_name(data, i) {
        IResult::Done(output, name) => {
            match be_i32(output) {
                IResult::Done(output, qtype) => {
                    match parse_class(output) {
                        IResult::Done(output, qclass) => {
                            IResult::Done(output,
                                          Question {
                                              qname: name,
                                              qtype: qtype,
                                              qclass: qclass,
                                          })
                        }
                        IResult::Error(e) => IResult::Error(e),
                        IResult::Incomplete(e) => IResult::Incomplete(e),
                    }
                }
                IResult::Error(e) => IResult::Error(e),
                IResult::Incomplete(e) => IResult::Incomplete(e),
            }
        }
        IResult::Error(e) => IResult::Error(e),
        IResult::Incomplete(e) => IResult::Incomplete(e),
    }
}
