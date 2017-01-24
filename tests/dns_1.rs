extern crate martin;

use martin::*;

#[test]
fn parse_query() {
    let data = include_bytes!("../assets/captures/dns_1_query.bin");
    let question = Question::new("google.com.", QType::ByType(Type::A), Class::Internet).unwrap();
    let msg = Message::parse(&data[..]).unwrap();
    assert!(msg.is_query());
    assert_eq!(msg.id(), 2);
    assert_eq!(msg.opcode(), Opcode::Query);
    assert_eq!(msg.questions, vec![question]);
}

#[test]
fn parse_response() {
    let data = include_bytes!("../assets/captures/dns_1_response.bin");
    let question = Question::new("google.com.", QType::ByType(Type::A), Class::Internet).unwrap();
    let rr = ResourceRecord::A {
        name: "google.com.".parse().unwrap(),
        class: Class::Internet,
        ttl: 299,
        addr: "172.217.3.206".parse().unwrap(),
    };
    let msg = Message::parse(&data[..]).unwrap();

    assert!(msg.is_response());
    assert_eq!(msg.id(), 2);
    assert_eq!(msg.opcode(), Opcode::Query);
    assert_eq!(msg.questions, vec![question]);
    assert_eq!(msg.answers, vec![rr]);
}

#[test]
fn parse_query_incomplete() {
    let data = include_bytes!("../assets/captures/dns_1_query.bin");
    let truncated = data.len() - 3;
    let msg = Message::parse(&data[..truncated]).unwrap_err();
    assert_eq!(format!("{}", msg), "Incomplete, expected 2 more bytes");
}
