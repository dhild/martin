use header::{Header, parse_header};
use nom::IResult;
use question::{Question, parse_question};
use rr::{ResourceRecord, parse_record};

/// Describes a DNS query or response.
#[warn(missing_debug_implementations)]
#[derive(Debug,Clone,PartialEq)]
pub struct Message {
    /// The message header
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

pub fn parse_message<'a>(data: &'a [u8]) -> IResult<&'a [u8], Message> {
    let header = parse_header(data);
    if let IResult::Done(mut output, header) = header {
        let mut questions = Vec::new();
        let mut answers = Vec::new();
        let mut authorities = Vec::new();
        let mut additionals = Vec::new();
        for _ in 0..header.question_count {
            match parse_question(data, output) {
                IResult::Error(e) => return IResult::Error(e),
                IResult::Incomplete(e) => return IResult::Incomplete(e),
                IResult::Done(o, q) => {
                    output = o;
                    questions.push(q);
                }
            }
        }
        for _ in 0..header.answer_count {
            match parse_record(data, output) {
                IResult::Error(e) => return IResult::Error(e),
                IResult::Incomplete(e) => return IResult::Incomplete(e),
                IResult::Done(o, rr) => {
                    output = o;
                    answers.push(rr);
                }
            }
        }
        for _ in 0..header.ns_count {
            match parse_record(data, output) {
                IResult::Error(e) => return IResult::Error(e),
                IResult::Incomplete(e) => return IResult::Incomplete(e),
                IResult::Done(o, rr) => {
                    output = o;
                    authorities.push(rr);
                }
            }
        }
        for _ in 0..header.additional_count {
            match parse_record(data, output) {
                IResult::Error(e) => return IResult::Error(e),
                IResult::Incomplete(e) => return IResult::Incomplete(e),
                IResult::Done(o, rr) => {
                    output = o;
                    additionals.push(rr);
                }
            }
        }
        return IResult::Done(output,
                             Message {
                                 header: header,
                                 questions: questions,
                                 answers: answers,
                                 authorities: authorities,
                                 additionals: additionals,
                             });
    };
    match header {
        IResult::Done(_, _) => unreachable!(),
        IResult::Error(e) => return IResult::Error(e),
        IResult::Incomplete(e) => return IResult::Incomplete(e),
    }
}

#[cfg(test)]
mod tests {
    use ::header::{Header, Opcode};
    use nom::IResult::Done;
    use ::question::{Question, QType};
    use ::rr::{Type, Class};
    use super::*;

    #[test]
    fn parse_query_1() {
        let data = include_bytes!("../assets/captures/dns_1_query.bin");
        let header = Header::query(2, Opcode::Query, true, 1);
        let question = Question::new("google.com.", QType::ByType(Type::A), Class::Internet)
            .unwrap();
        assert_eq!(parse_message(&data[..]),
                   Done(&b""[..],
                        Message {
                            header: header,
                            questions: vec![question],
                            answers: Vec::new(),
                            authorities: Vec::new(),
                            additionals: Vec::new(),
                        }));
    }

}
