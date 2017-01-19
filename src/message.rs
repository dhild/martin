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

impl Message {
    /// Parses the given message data into a `Message` object
    pub fn parse<'a>(data: &'a [u8]) -> IResult<&'a [u8], Message> {
        parse_message(data)
    }
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
    use ::rr::{Type, Class, ResourceRecord};
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

    #[test]
    fn parse_response_1() {
        let data = include_bytes!("../assets/captures/dns_1_response.bin");
        let query = Header::query(2, Opcode::Query, true, 1);
        let header = Header::response(query, true).answers(1);
        let question = Question::new("google.com.", QType::ByType(Type::A), Class::Internet)
            .unwrap();
        let rr = ResourceRecord::A {
            name: "google.com.".parse().unwrap(),
            class: Class::Internet,
            ttl: 299,
            addr: "172.217.3.206".parse().unwrap(),
        };
        assert_eq!(parse_message(&data[..]),
                   Done(&b""[..],
                        Message {
                            header: header,
                            questions: vec![question],
                            answers: vec![rr],
                            authorities: Vec::new(),
                            additionals: Vec::new(),
                        }));
    }

    #[test]
    fn parse_query_2() {
        let data = include_bytes!("../assets/captures/dns_2_query.bin");
        let header = Header::query(3, Opcode::Query, true, 1);
        let question = Question::new("google.com.", QType::ByType(Type::AAAA), Class::Internet)
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

    #[test]
    fn parse_response_2() {
        let data = include_bytes!("../assets/captures/dns_2_response.bin");
        let query = Header::query(3, Opcode::Query, true, 1);
        let header = Header::response(query, true).answers(1);
        let question = Question::new("google.com.", QType::ByType(Type::AAAA), Class::Internet)
            .unwrap();
        let rr = ResourceRecord::AAAA {
            name: "google.com.".parse().unwrap(),
            class: Class::Internet,
            ttl: 299,
            addr: "2607:f8b0:400a:809::200e".parse().unwrap(),
        };
        assert_eq!(parse_message(&data[..]),
                   Done(&b""[..],
                        Message {
                            header: header,
                            questions: vec![question],
                            answers: vec![rr],
                            authorities: Vec::new(),
                            additionals: Vec::new(),
                        }));
    }

    #[test]
    fn parse_query_3() {
        let data = include_bytes!("../assets/captures/dns_3_query.bin");
        let header = Header::query(0xda64, Opcode::Query, true, 1);
        let question = Question::new("tile-service.weather.microsoft.com.",
                                     QType::ByType(Type::AAAA),
                                     Class::Internet)
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

    #[test]
    fn parse_response_3() {
        let data = include_bytes!("../assets/captures/dns_3_response.bin");
        let query = Header::query(0xda64, Opcode::Query, true, 1);
        let header = Header::response(query, true).answers(2).authorities(1);
        let question = Question::new("tile-service.weather.microsoft.com.",
                                     QType::ByType(Type::AAAA),
                                     Class::Internet)
            .unwrap();
        let ans1 = ResourceRecord::CNAME {
            name: "tile-service.weather.microsoft.com.".parse().unwrap(),
            class: Class::Internet,
            ttl: 808,
            cname: "wildcard.weather.microsoft.com.edgekey.net.".parse().unwrap(),
        };
        let ans2 = ResourceRecord::CNAME {
            name: "wildcard.weather.microsoft.com.edgekey.net.".parse().unwrap(),
            class: Class::Internet,
            ttl: 466,
            cname: "e7070.g.akamaiedge.net.".parse().unwrap(),
        };
        let auth = ResourceRecord::SOA {
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
        };
        assert_eq!(parse_message(&data[..]),
                   Done(&b""[..],
                        Message {
                            header: header,
                            questions: vec![question],
                            answers: vec![ans1, ans2],
                            authorities: vec![auth],
                            additionals: Vec::new(),
                        }));
    }

    #[test]
    fn parse_query_4() {
        let data = include_bytes!("../assets/captures/dns_4_query.bin");
        let header = Header::query(0x60ff, Opcode::Query, true, 1).additional(1);
        let question = Question::new("gmail.com.", QType::Any, Class::Internet).unwrap();
        let opt = ResourceRecord::OPT {
            payload_size: 4096,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: false,
            data: vec![],
        };
        assert_eq!(parse_message(&data[..]),
                   Done(&b""[..],
                        Message {
                            header: header,
                            questions: vec![question],
                            answers: Vec::new(),
                            authorities: Vec::new(),
                            additionals: vec![opt],
                        }));
    }

    #[test]
    fn parse_response_4() {
        let data = include_bytes!("../assets/captures/dns_4_response.bin");
        let query = Header::query(0x60ff, Opcode::Query, true, 1).additional(1);
        let header = Header::response(query, true).answers(13).additional(1);
        let question = Question::new("gmail.com.", QType::Any, Class::Internet).unwrap();
        let opt = ResourceRecord::OPT {
            payload_size: 512,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: false,
            data: vec![],
        };
        let a = ResourceRecord::A {
            name: "gmail.com.".parse().unwrap(),
            class: Class::Internet,
            ttl: 299,
            addr: "216.58.216.165".parse().unwrap(),
        };
        let aaaa = ResourceRecord::AAAA {
            name: "gmail.com.".parse().unwrap(),
            class: Class::Internet,
            ttl: 299,
            addr: "2607:f8b0:400a:807::2005".parse().unwrap(),
        };
        let mx1 = ResourceRecord::MX {
            name: "gmail.com.".parse().unwrap(),
            class: Class::Internet,
            ttl: 3599,
            preference: 20,
            exchange: "alt2.gmail-smtp-in.l.google.com.".parse().unwrap(),
        };
        let ns1 = ResourceRecord::NS {
            name: "gmail.com.".parse().unwrap(),
            class: Class::Internet,
            ttl: 86399,
            ns_name: "ns3.google.com.".parse().unwrap(),
        };
        let ns2 = ResourceRecord::NS {
            name: "gmail.com.".parse().unwrap(),
            class: Class::Internet,
            ttl: 86399,
            ns_name: "ns4.google.com.".parse().unwrap(),
        };
        let soa = ResourceRecord::SOA {
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
        };
        let ns3 = ResourceRecord::NS {
            name: "gmail.com.".parse().unwrap(),
            class: Class::Internet,
            ttl: 86399,
            ns_name: "ns1.google.com.".parse().unwrap(),
        };
        let txt = ResourceRecord::TXT {
            name: "gmail.com.".parse().unwrap(),
            class: Class::Internet,
            ttl: 299,
            data: vec![String::from("v=spf1 redirect=_spf.google.com")],
        };
        let mx2 = ResourceRecord::MX {
            name: "gmail.com.".parse().unwrap(),
            class: Class::Internet,
            ttl: 3599,
            preference: 30,
            exchange: "alt3.gmail-smtp-in.l.google.com.".parse().unwrap(),
        };
        let ns4 = ResourceRecord::NS {
            name: "gmail.com.".parse().unwrap(),
            class: Class::Internet,
            ttl: 86399,
            ns_name: "ns2.google.com.".parse().unwrap(),
        };
        let mx3 = ResourceRecord::MX {
            name: "gmail.com.".parse().unwrap(),
            class: Class::Internet,
            ttl: 3599,
            preference: 40,
            exchange: "alt4.gmail-smtp-in.l.google.com.".parse().unwrap(),
        };
        let mx4 = ResourceRecord::MX {
            name: "gmail.com.".parse().unwrap(),
            class: Class::Internet,
            ttl: 3599,
            preference: 10,
            exchange: "alt1.gmail-smtp-in.l.google.com.".parse().unwrap(),
        };
        let mx5 = ResourceRecord::MX {
            name: "gmail.com.".parse().unwrap(),
            class: Class::Internet,
            ttl: 3599,
            preference: 5,
            exchange: "gmail-smtp-in.l.google.com.".parse().unwrap(),
        };
        let questions = vec![question];
        let answers = vec![a, aaaa, mx1, ns1, ns2, soa, ns3, txt, mx2, ns4, mx3, mx4, mx5];
        let additionals = vec![opt];
        let (_, res) = parse_message(&data[..]).unwrap();
        assert_eq!(res.header, header);
        assert_eq!(res.questions, questions);
        for i in 0..13 {
            assert_eq!(res.answers[i], answers[i]);
        }
        assert_eq!(res.answers, answers);
        assert_eq!(res.authorities, vec![]);
        assert_eq!(res.additionals, additionals);
        assert_eq!(parse_message(&data[..]),
                   Done(&b""[..],
                        Message {
                            header: header,
                            questions: questions,
                            answers: answers,
                            authorities: vec![],
                            additionals: additionals,
                        }));
    }

}
