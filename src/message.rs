use errors::ParseError;
use header::{Header, parse_header};
use header::{Opcode, Rcode};
use nom::{ErrorKind, IResult};
use nom::IResult::*;
use question::{Question, parse_question};
use rr::{ResourceRecord, parse_record};

/// Describes a DNS query or response.
#[warn(missing_debug_implementations)]
#[derive(Debug,Clone,PartialEq)]
pub struct Message {
    header: Header,
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
    /// Parses the given message data into a `Message` object
    pub fn parse(data: &[u8]) -> Result<Message, ParseError> {
        use nom::IResult::*;
        match do_parse_message(data) {
            Done(_, m) => Ok(m),
            Error(ErrorKind::Custom(e)) => Err(e),
            _ => Err(ParseError::Incomplete),
        }
    }

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
    pub fn query(id: u16, recursion_desired: bool, questions: &[Question]) -> Message {
        Message {
            header: Header::query(id, Opcode::Query, recursion_desired, questions.len() as u16),
            questions: questions.to_vec(),
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

    /// Adds an answer record to this `Message`
    pub fn push_answer(&mut self, ans: ResourceRecord) {
        self.header.answer_count += 1;
        self.answers.push(ans);
    }

    /// Adds an authority record to this `Message`
    pub fn push_authority(&mut self, auth: ResourceRecord) {
        self.header.ns_count += 1;
        self.authorities.push(auth);
    }

    /// Adds an additional record to this `Message`
    pub fn push_additional(&mut self, additional: ResourceRecord) {
        self.header.additional_count += 1;
        self.additionals.push(additional);
    }
}

fn do_parse_message(data: &[u8]) -> IResult<&[u8], Message, ParseError> {
    let (i, header) = try_parse!(data, parse_header);
    let (i, questions) = try_parse!(i, apply!(parse_questions, data, header.question_count));
    if questions.len() != header.question_count as usize {
        return Done(i,
                    Message {
                        header: header,
                        questions: questions,
                        answers: Vec::new(),
                        authorities: Vec::new(),
                        additionals: Vec::new(),
                    });
    }
    // No count checks - failures from an incomplete will fall through all three attempts.
    let (i, answers) = try_parse!(i, apply!(parse_records, data, header.answer_count));
    let (i, authorities) = try_parse!(i, apply!(parse_records, data, header.ns_count));
    let (i, additionals) = try_parse!(i, apply!(parse_records, data, header.additional_count));
    Done(i,
         Message {
             header: header,
             questions: questions,
             answers: answers,
             authorities: authorities,
             additionals: additionals,
         })
}

fn parse_questions<'a>(i: &'a [u8],
                       data: &'a [u8],
                       count: u16)
                       -> IResult<&'a [u8], Vec<Question>, ParseError> {
    let mut questions = Vec::with_capacity(count as usize);
    let mut input = i;
    for _ in 0..count {
        match parse_question(input, data) {
            Done(i, q) => {
                questions.push(q);
                input = i;
            }
            Incomplete(_) => return Done(input, questions),
            Error(e) => return Error(e),
        }
    }
    Done(input, questions)
}

fn parse_records<'a>(i: &'a [u8],
                     data: &'a [u8],
                     count: u16)
                     -> IResult<&'a [u8], Vec<ResourceRecord>, ParseError> {
    let mut records = Vec::with_capacity(count as usize);
    let mut input = i;
    for _ in 0..count {
        match parse_record(input, data) {
            Done(i, rr) => {
                records.push(rr);
                input = i;
            }
            Incomplete(_) => return Done(input, records),
            Error(e) => return Error(e),
        }
    }
    Done(input, records)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom::IResult::Done;
    use question::{Question, QType};
    use rr::{Type, Class, ResourceRecord};

    fn query_1() -> Message {
        let question = Question::new("google.com.", QType::ByType(Type::A), Class::Internet)
            .unwrap();
        Message::query(2, true, &[question])
    }

    #[test]
    fn parse_query_1() {
        let data = include_bytes!("../assets/captures/dns_1_query.bin");
        let msg = query_1();
        assert_eq!(do_parse_message(&data[..]), Done(&b""[..], msg));
    }

    #[test]
    fn parse_response_1() {
        let data = include_bytes!("../assets/captures/dns_1_response.bin");
        let mut msg = Message::response(query_1(), true);
        msg.push_answer(ResourceRecord::A {
                            name: "google.com.".parse().unwrap(),
                            class: Class::Internet,
                            ttl: 299,
                            addr: "172.217.3.206".parse().unwrap(),
                        });
        assert_eq!(do_parse_message(&data[..]), Done(&b""[..], msg));
    }

    fn query_2() -> Message {
        let question = Question::new("google.com.", QType::ByType(Type::AAAA), Class::Internet)
            .unwrap();
        Message::query(3, true, &[question])
    }

    #[test]
    fn parse_query_2() {
        let data = include_bytes!("../assets/captures/dns_2_query.bin");
        let msg = query_2();
        assert_eq!(do_parse_message(&data[..]), Done(&b""[..], msg));
    }

    #[test]
    fn parse_response_2() {
        let data = include_bytes!("../assets/captures/dns_2_response.bin");
        let mut msg = Message::response(query_2(), true);
        msg.push_answer(ResourceRecord::AAAA {
                            name: "google.com.".parse().unwrap(),
                            class: Class::Internet,
                            ttl: 299,
                            addr: "2607:f8b0:400a:809::200e".parse().unwrap(),
                        });
        assert_eq!(do_parse_message(&data[..]), Done(&b""[..], msg));
    }

    fn query_3() -> Message {
        let question = Question::new("tile-service.weather.microsoft.com.",
                                     QType::ByType(Type::AAAA),
                                     Class::Internet)
                .unwrap();
        Message::query(0xda64, true, &[question])
    }

    #[test]
    fn parse_query_3() {
        let data = include_bytes!("../assets/captures/dns_3_query.bin");
        let msg = query_3();
        assert_eq!(do_parse_message(&data[..]), Done(&b""[..], msg));
    }

    #[test]
    fn parse_response_3() {
        let data = include_bytes!("../assets/captures/dns_3_response.bin");
        let mut msg = Message::response(query_3(), true);
        msg.push_answer(ResourceRecord::CNAME {
                            name: "tile-service.weather.microsoft.com.".parse().unwrap(),
                            class: Class::Internet,
                            ttl: 808,
                            cname: "wildcard.weather.microsoft.com.edgekey.net.".parse().unwrap(),
                        });
        msg.push_answer(ResourceRecord::CNAME {
                            name: "wildcard.weather.microsoft.com.edgekey.net.".parse().unwrap(),
                            class: Class::Internet,
                            ttl: 466,
                            cname: "e7070.g.akamaiedge.net.".parse().unwrap(),
                        });
        msg.push_authority(ResourceRecord::SOA {
                               name: "g.akamaiedge.net.".parse().unwrap(),
                               class: Class::Internet,
                               ttl: 954,
                               mname: "n0g.akamaiedge.net.".parse().unwrap(),
                               rname: "hostmaster.akamai.com.".parse().unwrap(),
                               serial: 1484377525,
                               refresh: 1000,
                               retry: 1000,
                               expire: 1000,
                               minimum: 1800,
                           });
        println!("Size: {}",
                 do_parse_message(&data[..])
                     .unwrap()
                     .1
                     .answers
                     .len());
        assert_eq!(do_parse_message(&data[..]), Done(&b""[..], msg));
    }

    fn query_4() -> Message {
        let question = Question::new("gmail.com.", QType::Any, Class::Internet).unwrap();
        let mut msg = Message::query(0x60ff, true, &[question]);
        msg.push_additional(ResourceRecord::OPT {
                                payload_size: 4096,
                                extended_rcode: 0,
                                version: 0,
                                dnssec_ok: false,
                                data: vec![],
                            });
        msg
    }

    #[test]
    fn parse_query_4() {
        let data = include_bytes!("../assets/captures/dns_4_query.bin");
        let msg = query_4();
        assert_eq!(do_parse_message(&data[..]), Done(&b""[..], msg));
    }

    #[test]
    fn parse_response_4() {
        let data = include_bytes!("../assets/captures/dns_4_response.bin");
        let mut msg = Message::response(query_4(), true);
        msg.push_additional(ResourceRecord::OPT {
                                payload_size: 512,
                                extended_rcode: 0,
                                version: 0,
                                dnssec_ok: false,
                                data: vec![],
                            });
        msg.push_answer(ResourceRecord::A {
                            name: "gmail.com.".parse().unwrap(),
                            class: Class::Internet,
                            ttl: 299,
                            addr: "216.58.216.165".parse().unwrap(),
                        });
        msg.push_answer(ResourceRecord::AAAA {
                            name: "gmail.com.".parse().unwrap(),
                            class: Class::Internet,
                            ttl: 299,
                            addr: "2607:f8b0:400a:807::2005".parse().unwrap(),
                        });
        msg.push_answer(ResourceRecord::MX {
                            name: "gmail.com.".parse().unwrap(),
                            class: Class::Internet,
                            ttl: 3599,
                            preference: 20,
                            exchange: "alt2.gmail-smtp-in.l.google.com.".parse().unwrap(),
                        });
        msg.push_answer(ResourceRecord::NS {
                            name: "gmail.com.".parse().unwrap(),
                            class: Class::Internet,
                            ttl: 86399,
                            ns_name: "ns3.google.com.".parse().unwrap(),
                        });
        msg.push_answer(ResourceRecord::NS {
                            name: "gmail.com.".parse().unwrap(),
                            class: Class::Internet,
                            ttl: 86399,
                            ns_name: "ns4.google.com.".parse().unwrap(),
                        });
        msg.push_answer(ResourceRecord::SOA {
                            name: "gmail.com.".parse().unwrap(),
                            class: Class::Internet,
                            ttl: 59,
                            mname: "ns3.google.com.".parse().unwrap(),
                            rname: "dns-admin.google.com.".parse().unwrap(),
                            serial: 144520436,
                            refresh: 900,
                            retry: 900,
                            expire: 1800,
                            minimum: 60,
                        });
        msg.push_answer(ResourceRecord::NS {
                            name: "gmail.com.".parse().unwrap(),
                            class: Class::Internet,
                            ttl: 86399,
                            ns_name: "ns1.google.com.".parse().unwrap(),
                        });
        msg.push_answer(ResourceRecord::TXT {
                            name: "gmail.com.".parse().unwrap(),
                            class: Class::Internet,
                            ttl: 299,
                            data: vec![String::from("v=spf1 redirect=_spf.google.com")],
                        });
        msg.push_answer(ResourceRecord::MX {
                            name: "gmail.com.".parse().unwrap(),
                            class: Class::Internet,
                            ttl: 3599,
                            preference: 30,
                            exchange: "alt3.gmail-smtp-in.l.google.com.".parse().unwrap(),
                        });
        msg.push_answer(ResourceRecord::NS {
                            name: "gmail.com.".parse().unwrap(),
                            class: Class::Internet,
                            ttl: 86399,
                            ns_name: "ns2.google.com.".parse().unwrap(),
                        });
        msg.push_answer(ResourceRecord::MX {
                            name: "gmail.com.".parse().unwrap(),
                            class: Class::Internet,
                            ttl: 3599,
                            preference: 40,
                            exchange: "alt4.gmail-smtp-in.l.google.com.".parse().unwrap(),
                        });
        msg.push_answer(ResourceRecord::MX {
                            name: "gmail.com.".parse().unwrap(),
                            class: Class::Internet,
                            ttl: 3599,
                            preference: 10,
                            exchange: "alt1.gmail-smtp-in.l.google.com.".parse().unwrap(),
                        });
        msg.push_answer(ResourceRecord::MX {
                            name: "gmail.com.".parse().unwrap(),
                            class: Class::Internet,
                            ttl: 3599,
                            preference: 5,
                            exchange: "gmail-smtp-in.l.google.com.".parse().unwrap(),
                        });
        let (out, parsed) = do_parse_message(&data[..]).unwrap();
        assert_eq!(parsed.questions, msg.questions);
        for i in 0..13 {
            assert_eq!(parsed.answers[i], msg.answers[i]);
        }
        assert_eq!(parsed.answers, msg.answers);
        assert_eq!(parsed.authorities, msg.authorities);
        assert_eq!(parsed.additionals, msg.additionals);
        assert_eq!(out, &b""[..]);
    }

}
