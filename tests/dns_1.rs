extern crate martin;

use martin::*;

#[test]
fn parse_query_1() {
    let data = include_bytes!("../assets/captures/dns_1_query.bin");
    let question = Question::new("google.com.", QType::ByType(Type::A), Class::Internet).unwrap();
    let msg = Message::parse(&data[..]).unwrap();
    assert!(msg.is_query());
    assert_eq!(msg.id(), 2);
    assert_eq!(msg.opcode(), Opcode::Query);
    assert_eq!(msg.questions, vec![question]);
}

#[test]
fn parse_response_1() {
    let data = include_bytes!("../assets/captures/dns_1_response.bin");
    let question = Question::new("google.com.", QType::ByType(Type::A), Class::Internet).unwrap();
    let msg = Message::parse(&data[..]).unwrap();
    assert!(msg.is_response());
    assert_eq!(msg.id(), 2);
    assert_eq!(msg.opcode(), Opcode::Query);
    assert_eq!(msg.questions, vec![question]);
    // let query = Header::query(2, Opcode::Query, true, 1);
    // let header = Header::response(query, true).answers(1);
    // let question = Question::new("google.com.", QType::ByType(Type::A), Class::Internet)
    // .unwrap();
    // let rr = ResourceRecord::A {
    //     name: "google.com.".parse().unwrap(),
    //     class: Class::Internet,
    //     ttl: 299,
    //     addr: "172.217.3.206".parse().unwrap(),
    // };
    // assert_eq!(parse_message(&data[..]),
    //            Done(&b""[..],
    //                 Message {
    //                     header: header,
    //                     questions: vec![question],
    //                     answers: vec![rr],
    //                     authorities: Vec::new(),
    //                     additionals: Vec::new(),
    //                 }));
}
