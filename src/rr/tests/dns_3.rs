extern crate martin_rr;

use martin_rr::*;

#[test]
fn parse_query() {
    let data = include_bytes!("../assets/captures/dns_3_query.bin");
    let question = Question::new("tile-service.weather.microsoft.com.",
                                 QType::ByType(Type::AAAA),
                                 Class::Internet)
            .unwrap();
    let msg = Message::parse(&data[..]).unwrap();
    assert!(msg.is_query());
    assert_eq!(msg.id(), 0xda64);
    assert_eq!(msg.opcode(), Opcode::Query);
    assert_eq!(msg.questions, vec![question]);
}

#[test]
fn parse_response() {
    let data = include_bytes!("../assets/captures/dns_3_response.bin");
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
    let msg = Message::parse(&data[..]).unwrap();

    assert!(msg.is_response());
    assert_eq!(msg.id(), 0xda64);
    assert_eq!(msg.opcode(), Opcode::Query);
    assert_eq!(msg.questions, vec![question]);
    assert_eq!(msg.answers, vec![ans1, ans2]);
    assert_eq!(msg.authorities, vec![auth]);
}
