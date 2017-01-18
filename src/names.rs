use nom::{be_u8, be_u16, IResult, ErrorKind};
use nom::IResult::*;
use std::error;
use std::fmt;
use std::str::FromStr;

/// Representation of a domain name
///
/// Domain names consist of one or more labels, broken up by the character '.'.
#[derive(Debug,Hash,PartialEq,PartialOrd,Eq,Ord,Clone)]
pub struct Name {
    name: String,
}

impl Name {
    /// Returns the label for this `Name`
    pub fn label(&self) -> &str {
        match self.name.find('.') {
            Some(index) => &self.name[..index],
            None => &self.name,
        }
    }

    /// The parent is this `Name` without the left-most label
    pub fn parent(&self) -> Option<Name> {
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

    /// Gets the domain name as a `String`
    pub fn name(&self) -> &String {
        &self.name
    }
}

/// An error returned when parsing a domain name
#[derive(Debug,PartialEq,Clone,Copy)]
pub enum NameParseError {
    TotalLengthGreaterThan255(usize),
    LabelLengthGreaterThan63(usize),
    InvalidCharacter(char),
    HypenFirstCharacterInLabel,
    NameMustEndInRootLabel,
    EmptyNonRootLabel,
}

impl fmt::Display for NameParseError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        use std::error::Error;
        fmt.write_str(self.description())
    }
}

impl error::Error for NameParseError {
    fn description(&self) -> &str {
        "invalid domain name syntax"
    }
}


impl FromStr for Name {
    type Err = NameParseError;
    fn from_str(s: &str) -> Result<Name, NameParseError> {
        // Counting the `0` bit for the root label length, the str length must be < 254
        if s.len() > 254 {
            return Err(NameParseError::TotalLengthGreaterThan255(s.len()));
        }
        let mut label_len = 0;
        for c in s.chars() {
            match c {
                '.' => {
                    if label_len == 0 {
                        return Err(NameParseError::EmptyNonRootLabel);
                    }
                    if label_len > 63 {
                        return Err(NameParseError::LabelLengthGreaterThan63(label_len));
                    }
                    label_len = 0;
                }
                'a'...'z' | 'A'...'Z' | '0'...'9' => label_len += 1,
                '-' => {
                    if label_len == 0 {
                        return Err(NameParseError::HypenFirstCharacterInLabel);
                    }
                    label_len += 1;
                }
                c @ _ => return Err(NameParseError::InvalidCharacter(c)),
            }
        }
        if label_len != 0 {
            return Err(NameParseError::NameMustEndInRootLabel);
        }
        let name = String::from(s);
        Ok(Name { name: name })
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.name)
    }
}

/// Parses a byte stream into a `Name`
pub fn parse_name<'a>(data: &'a [u8], i: &'a [u8]) -> IResult<&'a [u8], Name> {
    match parse_name_to_string(data, i) {
        Done(output, name_string) => Done(output, Name { name: name_string }),
        Incomplete(e) => Incomplete(e),
        Error(e) => Error(error_node_position!(ErrorKind::Custom(300), i, e)),
    }
}

fn parse_name_to_string<'a>(data: &'a [u8], i: &'a [u8]) -> IResult<&'a [u8], String> {
    match i[0] {
        0 => parse_root(i),
        1...63 => parse_label(data, i),
        // Offsets:
        192...255 => parse_offset(data, i),
        // Unknown
        _ => Error(ErrorKind::Custom(1)),
    }
}

named!(parse_root<&[u8], String>,
    value!(String::from(""), tag!(&[ 0u8 ][..]))
);

fn parse_offset<'a>(data: &'a [u8], i: &'a [u8]) -> IResult<&'a [u8], String> {
    match be_u16(i) {
        Done(output, tag_and_offset) => {
            let offset = (tag_and_offset & 0b0011_1111_1111_1111) as usize;
            let i2 = &data[offset..];
            match parse_name_to_string(data, i2) {
                Done(_, name) => Done(output, name),
                Error(e) => Error(e),
                Incomplete(e) => Incomplete(e),
            }
        }
        Error(e) => Error(e),
        Incomplete(e) => Incomplete(e),
    }
}

fn parse_label<'a>(data: &'a [u8], i: &'a [u8]) -> IResult<&'a [u8], String> {
    match be_u8(i) {
        Done(output, length) => {
            match parse_label_bytes(output, length as usize) {
                Done(output, name_string) => {
                    parse_name_to_string(data, output).map(|rem: String| {
                        let mut s = String::from(name_string);
                        s.push_str(rem.as_str());
                        s
                    })
                }
                Error(e) => Error(e),
                Incomplete(e) => Incomplete(e),
            }
        }
        Error(e) => Error(e),
        Incomplete(e) => Incomplete(e),
    }
}

fn parse_label_bytes<'a>(i: &'a [u8], length: usize) -> IResult<&'a [u8], String> {
    match take!(i, length) {
        Done(output, bytes) => {
            match validate_label_to_string(bytes) {
                Ok(name_str) => {
                    let mut s = String::with_capacity(length + 1);
                    s.push_str(name_str);
                    s.push('.');
                    return Done(output, s);
                }
                Err(_) => Error(ErrorKind::Custom(100)),
            }
        }
        Error(e) => Error(e),
        Incomplete(e) => Incomplete(e),
    }
}

#[derive(Debug)]
enum ParseError {
    UTF8Error(::std::str::Utf8Error),
    HyphenFirstCharacterError(()),
    InvalidLabelCharacterError { c: char },
}

fn validate_label_to_string<'a>(input: &'a [u8]) -> ::std::result::Result<&'a str, ParseError> {
    for index in 0..input.len() {
        match input[index] as char {
            '-' if index == 0 => return Err(ParseError::HyphenFirstCharacterError(())),
            'a'...'z' | 'A'...'Z' | '0'...'9' | '-' => (),
            c @ _ => return Err(ParseError::InvalidLabelCharacterError { c: c }),
        }
    }
    match ::std::str::from_utf8(input) {
        Ok(v) => Ok(v),
        Err(e) => Err(ParseError::UTF8Error(e)),
    }
}

#[cfg(test)]
mod tests {
    use nom::IResult::Done;
    use super::*;

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
        let name = "raspberry.".parse::<Name>().unwrap();
        assert_eq!("raspberry", name.label());
    }

    #[test]
    fn simple_parent_is_root() {
        let name = "raspberry.".parse::<Name>().unwrap();
        let parent = name.parent().unwrap();
        assert_eq!("", parent.label());
    }

    #[test]
    fn multi_label_is_valid() {
        let name = "test.example.com.".parse::<Name>().unwrap();
        assert_eq!("test", name.label());
    }

    #[test]
    fn multi_parent_is_valid() {
        let name = "test.example.com.".parse::<Name>().unwrap();
        let parent1 = name.parent().unwrap();
        assert_eq!("example", parent1.label());
        let parent2 = parent1.parent().unwrap();
        assert_eq!("com", parent2.label());
        let parent3 = parent2.parent().unwrap();
        assert_eq!("", parent3.label());
    }

    #[test]
    fn name_parse_test() {
        // Contained names:
        // 20: F.ISI.ARPA.
        // 22: ISI.ARPA.
        // 26: ARPA.
        // 40: FOO.F.ISI.ARPA.
        // 46: <root>
        let a = b"12345678901234567890\x01F\x03ISI\x04ARPA\x0012345678\x03FOO\xC0\x14\x00abcd";

        assert_eq!(parse_name(&a[..], &a[20..]),
                   Done(&a[32..], Name { name: String::from("F.ISI.ARPA.") }));
        assert_eq!(parse_name(&a[..], &a[22..]),
                   Done(&a[32..], Name { name: String::from("ISI.ARPA.") }));
        assert_eq!(parse_name(&a[..], &a[40..]),
                   Done(&a[46..], Name { name: String::from("FOO.F.ISI.ARPA.") }));
        assert_eq!(parse_name(&a[..], &a[44..]),
                   Done(&a[46..], Name { name: String::from("F.ISI.ARPA.") }));
        assert_eq!(parse_name(&a[..], &a[46..]),
                   Done(&a[47..], Name { name: String::from("") }));
    }
}
