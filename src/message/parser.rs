use header::{Header, parse_header};
use nom::{IResult, Needed};
use nom::ErrorKind as nom_ek;
use nom::IResult::*;
use question::{Question, parse_question};
use rr::{ResourceRecord, parse_record};
use std::fmt;

/// Represents the possible kinds of errors from parsing a message.
#[derive(Debug,Clone,Copy)]
pub enum ErrorKind {
    Incomplete(Needed),
    FormatError(&'static str),
    LabelInvalidCharacter(char),
    LabelHyphenAsFirstCharacter(()),
}

impl ErrorKind {
    fn from(e: nom_ek) -> ErrorKind {
        match e {
            _ => ErrorKind::FormatError("Unparseable input"),
        }
    }
}

impl fmt::Display for ErrorKind {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        use self::ErrorKind::*;
        match *self {
            Incomplete(Needed::Size(x)) => write!(fmt, "Incomplete, expected {} more bytes", x),
            Incomplete(Needed::Unknown) => write!(fmt, "Incomplete, expected more bytes"),
            FormatError(s) => write!(fmt, "Formatting error: {}", s),
            LabelInvalidCharacter(c) => {
                write!(fmt,
                       "Valid label characters are a-z, A-Z, and '-'. Found: '\\x{:x}'",
                       c as u32)
            }
            LabelHyphenAsFirstCharacter(()) => {
                write!(fmt, "Hyphen ('-') found as the first character in a label")
            }
        }
    }
}

pub fn parse_message<'a>(i: &[u8])
                         -> Result<(Header,
                                    Vec<Question>,
                                    Vec<ResourceRecord>,
                                    Vec<ResourceRecord>,
                                    Vec<ResourceRecord>),
                                   ErrorKind> {
    match do_parse_message(i) {
        Done(_, o) => Ok(o),
        Incomplete(n) => Err(ErrorKind::Incomplete(n)),
        Error(e) => Err(ErrorKind::from(e)),
    }
}

pub fn do_parse_message<'a>(data: &[u8])
                            -> IResult<&[u8],
                                       (Header,
                                        Vec<Question>,
                                        Vec<ResourceRecord>,
                                        Vec<ResourceRecord>,
                                        Vec<ResourceRecord>)> {
    let (output, header) = try_parse!(data, parse_header);
    let (output, questions) = try_parse!(output,
                                         many_m_n!(header.question_count as usize,
                                                   header.question_count as usize,
                                                   apply!(parse_question, data)));
    let (output, ans) = try_parse!(output,
                                   many_m_n!(header.answer_count as usize,
                                             header.answer_count as usize,
                                             apply!(parse_record, data)));
    let (output, ns) = try_parse!(output,
                                  many_m_n!(header.ns_count as usize,
                                            header.ns_count as usize,
                                            apply!(parse_record, data)));
    let (output, additional) = try_parse!(output,
                                          many_m_n!(header.additional_count as usize,
                                                    header.additional_count as usize,
                                                    apply!(parse_record, data)));
    Done(output, (header, questions, ans, ns, additional))
}

#[cfg(test)]
mod tests {
    use super::*;
    use header::{Header, Opcode};
    use nom::IResult::Done;
    use question::{Question, QType};
    use rr::{Type, Class, ResourceRecord};

    #[test]
    fn parse_query_1() {
        let data = include_bytes!("../../assets/captures/dns_1_query.bin");
        let header = Header::query(2, Opcode::Query, true, 1);
        let question = Question::new("google.com.", QType::ByType(Type::A), Class::Internet)
            .unwrap();
        assert_eq!(do_parse_message(&data[..]),
                   Done(&b""[..],
                        (header, vec![question], Vec::new(), Vec::new(), Vec::new())));
    }

    #[test]
    fn parse_response_1() {
        let data = include_bytes!("../../assets/captures/dns_1_response.bin");
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
        assert_eq!(do_parse_message(&data[..]),
                   Done(&b""[..],
                        (header, vec![question], vec![rr], Vec::new(), Vec::new())));
    }

    #[test]
    fn parse_query_2() {
        let data = include_bytes!("../../assets/captures/dns_2_query.bin");
        let header = Header::query(3, Opcode::Query, true, 1);
        let question = Question::new("google.com.", QType::ByType(Type::AAAA), Class::Internet)
            .unwrap();
        assert_eq!(do_parse_message(&data[..]),
                   Done(&b""[..],
                        (header, vec![question], Vec::new(), Vec::new(), Vec::new())));
    }

    #[test]
    fn parse_response_2() {
        let data = include_bytes!("../../assets/captures/dns_2_response.bin");
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
        assert_eq!(do_parse_message(&data[..]),
                   Done(&b""[..],
                        (header, vec![question], vec![rr], Vec::new(), Vec::new())));
    }

    #[test]
    fn parse_query_3() {
        let data = include_bytes!("../../assets/captures/dns_3_query.bin");
        let header = Header::query(0xda64, Opcode::Query, true, 1);
        let question = Question::new("tile-service.weather.microsoft.com.",
                                     QType::ByType(Type::AAAA),
                                     Class::Internet)
                .unwrap();
        assert_eq!(do_parse_message(&data[..]),
                   Done(&b""[..],
                        (header, vec![question], Vec::new(), Vec::new(), Vec::new())));
    }

    #[test]
    fn parse_response_3() {
        let data = include_bytes!("../../assets/captures/dns_3_response.bin");
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
        assert_eq!(do_parse_message(&data[..]),
                   Done(&b""[..],
                        (header, vec![question], vec![ans1, ans2], vec![auth], Vec::new())));
    }

    #[test]
    fn parse_query_4() {
        let data = include_bytes!("../../assets/captures/dns_4_query.bin");
        let header = Header::query(0x60ff, Opcode::Query, true, 1).additional(1);
        let question = Question::new("gmail.com.", QType::Any, Class::Internet).unwrap();
        let opt = ResourceRecord::OPT {
            payload_size: 4096,
            extended_rcode: 0,
            version: 0,
            dnssec_ok: false,
            data: vec![],
        };
        assert_eq!(do_parse_message(&data[..]),
                   Done(&b""[..],
                        (header, vec![question], Vec::new(), Vec::new(), vec![opt])));
    }

    #[test]
    fn parse_response_4() {
        let data = include_bytes!("../../assets/captures/dns_4_response.bin");
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
        let (_, (r_header, r_questions, r_ans, r_auth, r_additionals)) =
            do_parse_message(&data[..]).unwrap();
        assert_eq!(r_header, header);
        assert_eq!(r_questions, questions);
        for i in 0..13 {
            assert_eq!(r_ans[i], answers[i]);
        }
        assert_eq!(r_ans, answers);
        assert_eq!(r_auth, vec![]);
        assert_eq!(r_additionals, additionals);
        assert_eq!(do_parse_message(&data[..]),
                   Done(&b""[..], (header, questions, answers, vec![], additionals)));
    }

}
