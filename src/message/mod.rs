pub use header::{Opcode, Rcode};
use header::Header;
use question::Question;
use rr::ResourceRecord;

mod parser;
pub use self::parser::ErrorKind;
use self::parser::parse_message;

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
    pub fn parse<'a>(data: &'a [u8]) -> Result<Message, ErrorKind> {
        parse_message(data).map(|args: (Header,
                                        Vec<Question>,
                                        Vec<ResourceRecord>,
                                        Vec<ResourceRecord>,
                                        Vec<ResourceRecord>)| {
            Message {
                header: args.0,
                questions: args.1,
                answers: args.2,
                authorities: args.3,
                additionals: args.4,
            }
        })
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
}

#[cfg(test)]
mod tests {

}
