extern crate martin;

use martin::*;

#[test]
fn parse_query() {
    let data = include_bytes!("../assets/captures/dns_4_query.bin");
    let question = Question::new("gmail.com.", QType::Any, Class::Internet).unwrap();
    let opt = ResourceRecord::OPT {
        payload_size: 4096,
        extended_rcode: 0,
        version: 0,
        dnssec_ok: false,
        data: vec![],
    };
    let msg = Message::parse(&data[..]).unwrap();
    assert!(msg.is_query());
    assert_eq!(msg.id(), 0x60ff);
    assert_eq!(msg.opcode(), Opcode::Query);
    assert_eq!(msg.questions, vec![question]);
    assert_eq!(msg.additionals, vec![opt]);
}

#[test]
fn parse_response() {
    let data = include_bytes!("../assets/captures/dns_4_response.bin");
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
    let msg = Message::parse(&data[..]).unwrap();

    assert!(msg.is_response());
    assert_eq!(msg.id(), 0x60ff);
    assert_eq!(msg.opcode(), Opcode::Query);
    assert_eq!(msg.questions, vec![question]);
    assert_eq!(msg.answers, vec![a, aaaa, mx1, ns1, ns2, soa, ns3, txt, mx2, ns4, mx3, mx4, mx5]);
    assert_eq!(msg.authorities, vec![]);
    assert_eq!(msg.additionals, vec![opt]);
}
