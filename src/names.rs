use nom::{be_u8, be_u16, IResult, ErrorKind};
use nom::IResult::*;
use std::error;
use std::fmt;
use std::str::FromStr;

/// Representation of a domain name
///
/// Domain names consist of one or more labels, broken up by the character '.'.
///
/// ```
/// # use martin::Name;
/// let name: Name = "test.example.com.".parse().unwrap();
/// assert_eq!("test", name.label());
/// assert_eq!("test.example.com.", name.to_string());
/// assert!(name != "test2.example.com.".parse().unwrap());
/// ```
#[derive(Debug,Hash,PartialEq,PartialOrd,Eq,Ord,Clone)]
pub struct Name {
    name: Vec<u8>,
}

impl Name {
    /// Returns the first label for this `Name`
    ///
    /// Labels in a domain name are broken up by the '.' character. A label is composed of the
    /// characters 'a'-'z', 'A'-'Z', and '-'.
    pub fn label(&self) -> &str {
        use std::str;
        let length: usize = self.name[0] as usize;
        str::from_utf8(&self.name[1..(length + 1)]).unwrap()
    }

    /// The parent is this `Name` without the left-most label
    pub fn parent(&self) -> Option<Name> {
        match self.name[0] {
            0 => None,
            skip @ _ => {
                let index: usize = 1 + skip as usize;
                let p = self.name[index..].to_vec();
                Some(Name { name: p })
            }
        }
    }

    /// Determines whether this name represents the root name.
    pub fn is_root(&self) -> bool {
        self.name == vec![0]
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
        use self::NameParseError::*;
        // Counting the `0` bit for the root label length, the str length must be < 254
        if s.len() > 254 {
            return Err(TotalLengthGreaterThan255(s.len()));
        }
        if s == "." {
            return Ok(Name { name: vec![0] });
        }
        let mut name: Vec<u8> = Vec::with_capacity(s.len() + 1);
        let mut last_label_index = 0;
        let mut label_len = 0;
        name.push(0); // First length byte
        for c in s.chars() {
            match c {
                '.' if label_len == 0 => return Err(EmptyNonRootLabel),
                '.' if label_len > 63 => return Err(LabelLengthGreaterThan63(label_len)),
                '.' => {
                    name[last_label_index] = label_len as u8;
                    last_label_index = name.len();
                    name.push(0);
                    label_len = 0;
                }
                '-' if label_len == 0 => return Err(HypenFirstCharacterInLabel),
                'a'...'z' | 'A'...'Z' | '0'...'9' | '-' => {
                    label_len += 1;
                    name.push(c as u8);
                }
                c @ _ => return Err(InvalidCharacter(c)),
            }
        }
        if label_len != 0 {
            return Err(NameMustEndInRootLabel);
        }
        Ok(Name { name: name })
    }
}

impl fmt::Display for Name {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        use std::str;
        let mut pos = 0;
        loop {
            match self.name[pos] {
                0 => break,
                length @ _ => {
                    let start = (pos + 1) as usize;
                    let end = start + length as usize;
                    let label = str::from_utf8(&self.name[start..end]).unwrap();
                    try!(write!(fmt, "{}.", label));
                    pos = end;
                }
            }
        }
        Ok(())
    }
}

/// Parses a byte stream into a `Name`
pub fn parse_name<'a>(i: &'a [u8], data: &'a [u8]) -> IResult<&'a [u8], Name> {
    return_error!(i,
                  ErrorKind::Custom(300),
                  map!(apply!(do_parse_name, data, Vec::with_capacity(255)),
                       |name_data: Vec<u8>| Name { name: name_data }))
}

fn do_parse_name<'a>(i: &'a [u8], data: &'a [u8], mut name: Vec<u8>) -> IResult<&'a [u8], Vec<u8>> {
    let (out, length) = try_parse!(&i, be_u8);
    match length {
        0 => {
            name.push(0);
            if name.len() > 255 {
                return Error(ErrorKind::Custom(1002));
            }
            return Done(out, name);
        }
        1...63 => {
            name.push(length);
            if (name.len() + (length as usize) + 1) > 255 {
                // Plus the ending '0' makes this > 255.
                return Error(ErrorKind::Custom(1003));
            }
            let (out2, bytes) = try_parse!(out, take!(length));
            for (index, c) in bytes.iter().enumerate() {
                match *c as char {
                    '-' if index == 0 => return Error(ErrorKind::Custom(1004)),
                    'a'...'z' | 'A'...'Z' | '0'...'9' | '-' => name.push(*c),
                    _ => return Error(ErrorKind::Custom(1005)),
                }
            }
            do_parse_name(out2, data, name)
        }
        // Offsets:
        192...255 => {
            let (output, offset) =
                try_parse!(i,
                           map!(be_u16, |t_o: u16| (t_o & 0b0011_1111_1111_1111) as usize));
            let (_, n) = try_parse!(data,
                                    do_parse!(
                                        take!(offset) >>
                                        n: apply!(do_parse_name, data, name) >>
                                        (n)
                                    ));
            Done(output, n)
        }
        // Unknown: reserved bits.
        _ => return Error(ErrorKind::Custom(1001)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nom::IResult::Done;

    #[test]
    fn parse_str_root_label() {
        let name = "".parse::<Name>().unwrap();
        assert_eq!("", name.label());
        assert_eq!("", name.to_string());
        assert!(name.is_root());
        assert_eq!(None, name.parent());
    }

    #[test]
    fn parse_str_simple_label() {
        let name = "raspberry.".parse::<Name>().unwrap();
        println!("{}, {:?}", name.to_string(), name);
        assert_eq!("raspberry", name.label());
        assert_eq!("raspberry.", name.to_string());
        assert!(!name.is_root());
        assert!(name.parent().unwrap().is_root());
    }

    #[test]
    fn parse_str_multi_label() {
        let name = "test.example.com.".parse::<Name>().unwrap();
        assert_eq!("test", name.label());
        assert_eq!("test.example.com.", name.to_string());
        assert!(!name.is_root());
        let parent = name.parent().unwrap();
        assert!(!parent.is_root());
        assert_eq!("example", parent.label());
        assert_eq!("example.com.", parent.to_string());
        let parent = parent.parent().unwrap();
        assert!(!parent.is_root());
        assert_eq!("com", parent.label());
        assert_eq!("com.", parent.to_string());
        assert!(parent.parent().unwrap().is_root());
    }

    #[test]
    fn name_parse_bytes_test() {
        // Contained names:
        // 20: F.ISI.ARPA.
        // 22: ISI.ARPA.
        // 26: ARPA.
        // 40: FOO.F.ISI.ARPA.
        // 46: <root>
        let a = b"12345678901234567890\x01F\x03ISI\x04ARPA\x0012345678\x03FOO\xC0\x14\x00abcd";

        assert_eq!(parse_name(&a[20..], &a[..]),
                   Done(&a[32..],
                        Name { name: b"\x01F\x03ISI\x04ARPA\x00".to_vec() }));
        assert_eq!(parse_name(&a[22..], &a[..]),
                   Done(&a[32..], Name { name: b"\x03ISI\x04ARPA\x00".to_vec() }));
        assert_eq!(parse_name(&a[40..], &a[..]),
                   Done(&a[46..],
                        Name { name: b"\x03FOO\x01F\x03ISI\x04ARPA\x00".to_vec() }));
        // This one is fun: make sure that extra names aren't swallowed or parsed:
        assert_eq!(parse_name(&a[44..], &a[..]),
                   Done(&b"\x00abcd"[..],
                        Name { name: b"\x01F\x03ISI\x04ARPA\x00".to_vec() }));
        assert_eq!(parse_name(&a[46..], &a[..]),
                   Done(&b"abcd"[..], Name { name: b"\x00".to_vec() }));
    }

    #[test]
    fn name_parse_errors() {
        use super::NameParseError::*;
        let name = {
            let mut s = String::from("test.");
            while s.len() < 255 {
                s += "test.";
            }
            s
        };
        assert_eq!(name.parse::<Name>(),
                   Err(TotalLengthGreaterThan255(name.len())));

        let name = {
            let mut s = String::from("test");
            while s.len() < 63 {
                s += "test";
            }
            s += ".";
            s
        };
        assert_eq!(name.parse::<Name>(),
                   Err(LabelLengthGreaterThan63(name.len() - 1)));

        let name = "test!.";
        assert_eq!(name.parse::<Name>(), Err(InvalidCharacter('!')));

        let name = "-test.";
        assert_eq!(name.parse::<Name>(), Err(HypenFirstCharacterInLabel));
        let name = "te.st";
        assert_eq!(name.parse::<Name>(), Err(NameMustEndInRootLabel));
        let name = "test..";
        assert_eq!(name.parse::<Name>(), Err(EmptyNonRootLabel));
    }
}
