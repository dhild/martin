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

    /// Determines whether this name represents the root name.
    pub fn is_root(&self) -> bool {
        self.name.len() == 0
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
        use self::NameParseError::*;
        match *self {
            TotalLengthGreaterThan255(x) => {
                write!(fmt, "Name length must be less than 255, was {}", x)
            }
            LabelLengthGreaterThan63(x) => {
                write!(fmt, "Label length must be less than 63, was {}", x)
            }
            InvalidCharacter(x) => {
                write!(fmt,
                       "Valid characters are a-z, A-Z, and '-'. Found: '\\x{:x}'",
                       x as u32)
            }
            HypenFirstCharacterInLabel => {
                write!(fmt, "Hyphen ('-') cannot be the first character in a label")
            }
            NameMustEndInRootLabel => write!(fmt, "Names must end in the root label ('.')"),
            EmptyNonRootLabel => {
                write!(fmt,
                       "The root label is only allowed at the end of names (found \"..\")")
            }
        }
    }
}

impl error::Error for NameParseError {
    fn description(&self) -> &str {
        use self::NameParseError::*;
        match *self {
            TotalLengthGreaterThan255(_) => "Name length must be less than 255",
            LabelLengthGreaterThan63(_) => "Label length must be less than 63",
            InvalidCharacter(_) => "Valid characters are a-z, A-Z, and '-'.",
            HypenFirstCharacterInLabel => "Hyphen ('-') cannot be the first character in a label",
            NameMustEndInRootLabel => "Names must end in the root label ('.')",
            EmptyNonRootLabel => "The root label is only allowed at the end of names",
        }
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
pub fn parse_name<'a>(i: &'a [u8], data: &'a [u8]) -> IResult<&'a [u8], Name> {
    return_error!(i,
                  ErrorKind::Custom(300),
                  map!(apply!(parse_name_to_string, data),
                       |name_string: String| Name { name: name_string }))
}

fn parse_name_to_string<'a>(i: &'a [u8], data: &'a [u8]) -> IResult<&'a [u8], String> {
    let (_, tag) = try_parse!(i, be_u8);
    match tag {
        0 => parse_root(i),
        1...63 => parse_label(i, data),
        // Offsets:
        192...255 => parse_offset(i, data),
        // Unknown
        _ => Error(ErrorKind::Custom(1)),
    }
}

named!(parse_root<&[u8], String>, value!(String::from(""), tag!(&[ 0u8 ][..])));

fn parse_offset<'a>(i: &'a [u8], data: &'a [u8]) -> IResult<&'a [u8], String> {
    let (output, offset) =
        try_parse!(i, map!(be_u16, |t_o: u16| {(t_o & 0b0011_1111_1111_1111) as usize}));
    let (_, name) = try_parse!(&data[offset..], apply!(parse_name_to_string, data));
    Done(output, name)
}

fn parse_label<'a>(i: &'a [u8], data: &'a [u8]) -> IResult<&'a [u8], String> {
    do_parse!(i,
        length: be_u8 >>
        label: map_res!(take!(length), validate_label_to_string) >>
        rem: apply!(parse_name_to_string, data) >>
        ({label.to_string() + "." + &rem})
    )
}

#[derive(Debug)]
enum ParseError {
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
        Err(_) => unreachable!(),
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

        assert_eq!(parse_name(&a[20..], &a[..]),
                   Done(&a[32..], Name { name: String::from("F.ISI.ARPA.") }));
        assert_eq!(parse_name(&a[22..], &a[..]),
                   Done(&a[32..], Name { name: String::from("ISI.ARPA.") }));
        assert_eq!(parse_name(&a[40..], &a[..]),
                   Done(&a[46..], Name { name: String::from("FOO.F.ISI.ARPA.") }));
        // This one is fun: make sure that extra names aren't swallowed or parsed:
        assert_eq!(parse_name(&a[44..], &a[..]),
                   Done(&b"\x00abcd"[..], Name { name: String::from("F.ISI.ARPA.") }));
        assert_eq!(parse_name(&a[46..], &a[..]),
                   Done(&b"abcd"[..], Name { name: String::from("") }));
    }

}
