extern crate martin;

use martin::*;

#[test]
fn parse_query() {
    let data = include_bytes!("../assets/captures/dns_2_query.bin");
    let question = Question::new("google.com.", QType::ByType(Type::AAAA), Class::Internet)
        .unwrap();
    let msg = Message::parse(&data[..]).unwrap();
    assert!(msg.is_query());
    assert_eq!(msg.id(), 3);
    assert_eq!(msg.opcode(), Opcode::Query);
    assert_eq!(msg.questions, vec![question]);
}

#[test]
fn parse_response() {
    let data = include_bytes!("../assets/captures/dns_2_response.bin");
    let question = Question::new("google.com.", QType::ByType(Type::AAAA), Class::Internet)
        .unwrap();
    let rr = ResourceRecord::AAAA {
        name: "google.com.".parse().unwrap(),
        class: Class::Internet,
        ttl: 299,
        addr: "2607:f8b0:400a:809::200e".parse().unwrap(),
    };
    let msg = Message::parse(&data[..]).unwrap();

    assert!(msg.is_response());
    assert_eq!(msg.id(), 3);
    assert_eq!(msg.opcode(), Opcode::Query);
    assert_eq!(msg.questions, vec![question]);
    assert_eq!(msg.answers, vec![rr]);
}
