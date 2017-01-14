use nom::{IResult, be_u16};

/// Header for resource record queries and responses
#[derive(Debug,Clone,Copy)]
pub struct Header {
    /// A 16 bit identifier assigned by the program.
    pub id: u16,
    /// Specifies whether this message is a query.
    pub qr: bool,
    opcode: u8,
    /// Whether the response is authoritative
    pub aa: bool,
    /// Whether the response is truncated
    pub tc: bool,
    /// Whether recursion is desired
    pub rd: bool,
    /// Whether recursion is available
    pub ra: bool,
    /// The response code
    pub rcode: u8,
    /// The number of entries in the question section.
    pub qdcount: u16,
    /// The number of entries in the resource records section.
    pub ancount: u16,
    /// The number of entries in the authority records section.
    pub nscount: u16,
    /// The number of entries in the additional records section.
    pub arcount: u16,
}

impl Header {
    /// Parses a byte stream into a `Header`
    pub fn parser(i: &[u8]) -> IResult<&[u8], Header> {
        header(i)
    }
}

//                                 1  1  1  1  1  1
//   0  1  2  3  4  5  6  7  8  9  0  1  2  3  4  5
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                      ID                       |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |QR|   Opcode  |AA|TC|RD|RA|   Z    |   RCODE   |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    QDCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ANCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    NSCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
// |                    ARCOUNT                    |
// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+

struct Flags {
    qr: bool,
    opcode: u8,
    aa: bool,
    tc: bool,
    rd: bool,
    ra: bool,
    rcode: u8,
}

named!(header_flags<&[u8], Flags>,
bits!(do_parse!(
     qr:     take_bits!( u8, 1 ) >>
     opcode: take_bits!( u8, 4 ) >>
     aa:     take_bits!( u8, 1 ) >>
     tc:     take_bits!( u8, 1 ) >>
     rd:     take_bits!( u8, 1 ) >>
     ra:     take_bits!( u8, 1 ) >>
     zero:   take_bits!( u8, 3 ) >>
     rcode:  take_bits!( u8, 4 ) >>
     (Flags {
          qr: (qr == 1),
          opcode: opcode,
          aa: (aa == 1),
          tc: (tc == 1),
          rd: (rd == 1),
          ra: (ra == 1),
          rcode: rcode
      })
)));

named!(header<&[u8], Header>,
do_parse!(
    id:          be_u16 >>
    flags: header_flags >>
    qdcount:     be_u16 >>
    ancount:     be_u16 >>
    nscount:     be_u16 >>
    arcount:     be_u16 >>
    (Header {
        id: id,
        qr: flags.qr,
        opcode: flags.opcode,
        aa: flags.aa,
        tc: flags.tc,
        rd: flags.rd,
        ra: flags.ra,
        rcode: flags.rcode,
        qdcount: qdcount,
        ancount: ancount,
        nscount: nscount,
        arcount: arcount
    })
));

#[cfg(test)]
mod tests {
    use nom::IResult;
    use super::Header;

    #[test]
    fn parse_query_1_header() {
        let data = include_bytes!("../assets/captures/dns_1_query.bin");
        let header = match Header::parser(&data[0..12]) {
            IResult::Done(_, res) => res,
            _ => panic!("Result not parsed correctly"),
        };
        assert_eq!(header.id, 2);
        assert!(!header.qr);
        assert!(!header.aa);
        assert!(!header.tc);
        assert!(header.rd);
        assert!(!header.ra);
        assert_eq!(0, header.rcode);
        assert_eq!(1, header.qdcount);
        assert_eq!(0, header.ancount);
        assert_eq!(0, header.nscount);
        assert_eq!(0, header.arcount);
    }

    #[test]
    fn parse_response_1_header() {
        let data = include_bytes!("../assets/captures/dns_1_response.bin");
        let header = match Header::parser(&data[0..12]) {
            IResult::Done(_, res) => res,
            _ => panic!("Result not parsed correctly"),
        };
        assert!(header.qr);
        assert_eq!(header.id, 2);
        assert!(!header.aa);
        assert!(!header.tc);
        assert!(header.rd);
        assert!(header.ra);
        assert_eq!(0, header.rcode);
        assert_eq!(1, header.qdcount);
        assert_eq!(1, header.ancount);
        assert_eq!(0, header.nscount);
        assert_eq!(0, header.arcount);
    }

    #[test]
    fn parse_query_2_header() {
        let data = include_bytes!("../assets/captures/dns_2_query.bin");
        let header = match Header::parser(&data[0..12]) {
            IResult::Done(_, res) => res,
            _ => panic!("Result not parsed correctly"),
        };
        assert_eq!(header.id, 3);
        assert!(!header.qr);
        assert!(!header.aa);
        assert!(!header.tc);
        assert!(header.rd);
        assert!(!header.ra);
        assert_eq!(0, header.rcode);
        assert_eq!(1, header.qdcount);
        assert_eq!(0, header.ancount);
        assert_eq!(0, header.nscount);
        assert_eq!(0, header.arcount);
    }

    #[test]
    fn parse_response_2_header() {
        let data = include_bytes!("../assets/captures/dns_2_response.bin");
        let header = match Header::parser(&data[0..12]) {
            IResult::Done(_, res) => res,
            _ => panic!("Result not parsed correctly"),
        };
        assert!(header.qr);
        assert_eq!(header.id, 3);
        assert!(!header.aa);
        assert!(!header.tc);
        assert!(header.rd);
        assert!(header.ra);
        assert_eq!(0, header.rcode);
        assert_eq!(1, header.qdcount);
        assert_eq!(1, header.ancount);
        assert_eq!(0, header.nscount);
        assert_eq!(0, header.arcount);
    }

    #[test]
    fn parse_query_3_header() {
        let data = include_bytes!("../assets/captures/dns_3_query.bin");
        let header = match Header::parser(&data[0..12]) {
            IResult::Done(_, res) => res,
            _ => panic!("Result not parsed correctly"),
        };
        assert_eq!(header.id, 0xda64);
        assert!(!header.qr);
        assert!(!header.aa);
        assert!(!header.tc);
        assert!(header.rd);
        assert!(!header.ra);
        assert_eq!(0, header.rcode);
        assert_eq!(1, header.qdcount);
        assert_eq!(0, header.ancount);
        assert_eq!(0, header.nscount);
        assert_eq!(0, header.arcount);
    }

    #[test]
    fn parse_response_3_header() {
        let data = include_bytes!("../assets/captures/dns_3_response.bin");
        let header = match Header::parser(&data[0..12]) {
            IResult::Done(_, res) => res,
            _ => panic!("Result not parsed correctly"),
        };
        assert!(header.qr);
        assert_eq!(header.id, 0xda64);
        assert!(!header.aa);
        assert!(!header.tc);
        assert!(header.rd);
        assert!(header.ra);
        assert_eq!(0, header.rcode);
        assert_eq!(1, header.qdcount);
        assert_eq!(2, header.ancount);
        assert_eq!(1, header.nscount);
        assert_eq!(0, header.arcount);
    }

    #[test]
    fn parse_query_4_header() {
        let data = include_bytes!("../assets/captures/dns_4_query.bin");
        let header = match Header::parser(&data[0..12]) {
            IResult::Done(_, res) => res,
            IResult::Error(err) => {
                println!("{:?}", err);
                panic!("Result not parsed correctly (Error)");
            },
            IResult::Incomplete(needed) => {
                println!("{:?}", needed);
                panic!("Result not parsed correctly (Incomplete)");
            },
        };
        assert_eq!(header.id, 0x60ff);
        assert!(!header.qr);
        assert!(!header.aa);
        assert!(!header.tc);
        assert!(header.rd);
        assert!(!header.ra);
        assert_eq!(0, header.rcode);
        assert_eq!(1, header.qdcount);
        assert_eq!(0, header.ancount);
        assert_eq!(0, header.nscount);
        assert_eq!(1, header.arcount);
    }

    #[test]
    fn parse_response_4_header() {
        let data = include_bytes!("../assets/captures/dns_4_response.bin");
        let header = match Header::parser(&data[0..12]) {
            IResult::Done(_, res) => res,
            _ => panic!("Result not parsed correctly"),
        };
        assert!(header.qr);
        assert_eq!(header.id, 0x60ff);
        assert!(!header.aa);
        assert!(!header.tc);
        assert!(header.rd);
        assert!(header.ra);
        assert_eq!(0, header.rcode);
        assert_eq!(1, header.qdcount);
        assert_eq!(13, header.ancount);
        assert_eq!(0, header.nscount);
        assert_eq!(1, header.arcount);
    }
}
