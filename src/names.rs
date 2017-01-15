use nom::{be_u8, be_u16, IResult, ErrorKind};
use std::error::Error;
use std::fmt;
use std::str::FromStr;

/// Representation of a domain name
///
/// Domain names consist of one or more labels, broken up by the character '.'.
#[derive(Debug,Hash,PartialEq,PartialOrd,Eq,Ord,Clone)]
pub struct Name {
    name: String,
}

fn first_label(name: &str) -> &str {
    match name.find('.') {
        Some(index) => &name[..index],
        None => name,
    }
}

impl Name {
    fn label(&self) -> &str {
        first_label(&self.name)
    }

    fn parent(&self) -> Option<Name> {
        match self.name.find('.') {
            Some(index) => Some(Name { name: String::from(&self.name[(index + 1)..]) }),
            None => {
                match self.name.len() {
                    0 => None,
                    _ => Some(Name { name: String::from("") }),
                }
            }
        }
    }

    fn name(&self) -> &String {
        &self.name
    }

    /// Parses a byte stream into a `Name`
    pub fn parser<'a>(data: &'a [u8], i: &'a [u8]) -> IResult<&'a [u8], Name> {
        parse_name(data, i)
    }
}

/// An error returned when parsing a domain name
#[derive(Debug,PartialEq,Clone,Copy)]
pub struct NameParseError(());

impl fmt::Display for NameParseError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        fmt.write_str(self.description())
    }
}

impl Error for NameParseError {
    fn description(&self) -> &str {
        "invalid domain name syntax"
    }
}


impl FromStr for Name {
    type Err = NameParseError;
    fn from_str(s: &str) -> Result<Name, NameParseError> {
        let name = String::from(s);
        Ok(Name { name: name })
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

fn parse_name<'a>(data: &'a [u8], i: &'a [u8]) -> IResult<&'a [u8], Name> {
    match i[0] {
        0 => parse_root(i),
        1...63 => parse_label(data, i),
        // Offsets:
        192...255 => parse_offset(data, i),
        // Unknown
        _ => IResult::Error(ErrorKind::Custom(1)),
    }
}

named!(parse_root<&[u8], Name>,
do_parse!(
    tag!(&[ 0u8 ][..]) >>
    take!(1) >>
    (Name { name: String::from("") })
));

fn parse_offset<'a>(data: &'a [u8], i: &'a [u8]) -> IResult<&'a [u8], Name> {
    match be_u16(i) {
        IResult::Done(output, tag_and_offset) => {
            let offset = (tag_and_offset & 0b0011_1111_1111_1111) as usize;
            let i2 = &data[offset..];
            parse_name(data, i2)
        }
        IResult::Error(e) => IResult::Error(e),
        IResult::Incomplete(e) => IResult::Incomplete(e),
    }
}

fn parse_label<'a>(data: &'a [u8], i: &'a [u8]) -> IResult<&'a [u8], Name> {
    match be_u8(i) {
        IResult::Done(output, length) => {
            match parse_label_bytes(output, length as usize) {
                IResult::Done(output, name_string) => {
                    match parse_name(data, output) {
                        IResult::Done(output, rem) => {
                            let mut s = String::from(name_string);
                            s.push_str(rem.name().as_str());
                            let name = Name { name: s };
                            IResult::Done(output, name)
                        }
                        IResult::Error(e) => IResult::Error(e),
                        IResult::Incomplete(e) => IResult::Incomplete(e),
                    }
                }
                IResult::Error(e) => IResult::Error(e),
                IResult::Incomplete(e) => IResult::Incomplete(e),
            }
        }
        IResult::Error(e) => IResult::Error(e),
        IResult::Incomplete(e) => IResult::Incomplete(e),
    }
}

fn parse_label_bytes<'a>(i: &'a [u8], length: usize) -> IResult<&'a [u8], String> {
    match take!(i, length) {
        IResult::Done(output, bytes) => {
            match validate_label_to_string(bytes) {
                Ok(name_str) => {
                    let mut s = String::with_capacity(length + 1);
                    s.push_str(name_str);
                    s.push('.');
                    return ::nom::IResult::Done(output, s);
                }
                Err(_) => IResult::Error(ErrorKind::Custom(100)),
            }
        }
        IResult::Error(e) => IResult::Error(e),
        IResult::Incomplete(e) => IResult::Incomplete(e),
    }
}

enum ParseError {
    UTF8Error(::std::str::Utf8Error),
    HyphenFirstCharacterError(()),
    InvalidLabelCharacterError(()),
}

fn validate_label_to_string<'a>(input: &'a [u8]) -> ::std::result::Result<&'a str, ParseError> {
    for index in 0..input.len() {
        match input[index] as char {
            'a'...'z' | 'A'...'Z' | '0'...'9' => (),
            '-' if index == 0 => return Err(ParseError::HyphenFirstCharacterError(())),
            _ => return Err(ParseError::InvalidLabelCharacterError(())),
        }
    }
    match ::std::str::from_utf8(input) {
        Ok(v) => Ok(v),
        Err(e) => Err(ParseError::UTF8Error(e)),
    }
}

#[cfg(test)]
mod tests {
    use super::Name;

    #[test]
    fn root_label_is_valid() {
        let name = "".parse::<Name>().unwrap();
        assert_eq!("", name.label());
    }

    #[test]
    fn root_parent_is_none() {
        let name = "".parse::<Name>().unwrap();
        assert_eq!(None, name.parent());
    }

    #[test]
    fn simple_label_is_valid() {
        let name = "raspberry".parse::<Name>().unwrap();
        assert_eq!("raspberry", name.label());
    }

    #[test]
    fn simple_parent_is_root() {
        let name = "raspberry".parse::<Name>().unwrap();
        let parent = name.parent().unwrap();
        assert_eq!("", parent.label());
    }

    #[test]
    fn multi_label_is_valid() {
        let name = "test.example.com".parse::<Name>().unwrap();
        assert_eq!("test", name.label());
    }

    #[test]
    fn multi_parent_is_valid() {
        let name = "test.example.com".parse::<Name>().unwrap();
        let parent1 = name.parent().unwrap();
        assert_eq!("example", parent1.label());
        let parent2 = parent1.parent().unwrap();
        assert_eq!("com", parent2.label());
        let parent3 = parent2.parent().unwrap();
        assert_eq!("", parent3.label());
    }
}
