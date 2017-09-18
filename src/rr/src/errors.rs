use names::NameParseError;
use nom::{IResult, Needed};
use nom::ErrorKind;
use nom::IResult::*;
use rr::Type;
use std::convert::From;
use std::error;
use std::fmt;

/// Errors that may occur while parsing
#[derive(Debug,PartialEq,Clone,Copy)]
pub enum ParseError {
    /// An insufficient number of bytes were provided
    Incomplete,
    /// An error occured while parsing a name
    NameError(NameParseError),
    /// A resource record length field is invalid
    InvalidRecordLength(Type),
    /// An OPT record has a name field other than the root name
    OptNameNotRoot,
    /// A TXT record has an invalid character string
    TxtInvalidUtf8,
}

impl From<NameParseError> for ParseError {
    fn from(error: NameParseError) -> ParseError {
        ParseError::NameError(error)
    }
}

pub fn make_error(e: NameParseError) -> ErrorKind<ParseError> {
    ErrorKind::Custom(ParseError::from(e))
}


impl fmt::Display for ParseError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        use self::ParseError::*;
        match *self {
            Incomplete => write!(fmt, "Insufficient bytes supplied to parse."),
            NameError(e) => write!(fmt, "{}", e),
            InvalidRecordLength(t) => write!(fmt, "Invalid record length field for type {}.", t),
            OptNameNotRoot => write!(fmt, "Name for OPT record was not root name."),
            TxtInvalidUtf8 => write!(fmt, "Invalid UTF-8 in TXT string."),
        }
    }
}

impl error::Error for ParseError {
    fn description(&self) -> &str {
        use self::ParseError::*;
        match *self {
            Incomplete => "Insufficient bytes supplied to parse.",
            NameError(ref e) => e.description(),
            InvalidRecordLength { .. } => "Invalid record length field.",
            OptNameNotRoot => "Name for OPT record was not root name.",
            TxtInvalidUtf8 => "Invalid UTF-8 in TXT string.",
        }
    }
}

pub fn be_u8(i: &[u8]) -> IResult<&[u8], u8, ParseError> {
    if i.len() < 1 {
        Incomplete(Needed::Size(1))
    } else {
        Done(&i[1..], i[0])
    }
}

pub fn be_u16(i: &[u8]) -> IResult<&[u8], u16, ParseError> {
    if i.len() < 2 {
        Incomplete(Needed::Size(2))
    } else {
        let res = ((i[0] as u16) << 8) + i[1] as u16;
        Done(&i[2..], res)
    }
}

pub fn be_u32(i: &[u8]) -> IResult<&[u8], u32, ParseError> {
    if i.len() < 4 {
        Incomplete(Needed::Size(4))
    } else {
        let res = ((i[0] as u32) << 24) + ((i[1] as u32) << 16) + ((i[2] as u32) << 8) +
                  i[3] as u32;
        Done(&i[4..], res)
    }
}

pub fn be_i32(i: &[u8]) -> IResult<&[u8], i32, ParseError> {
    map!(i, be_u32, |x| x as i32)
}

pub fn take(i: &[u8], count: u16) -> IResult<&[u8], &[u8], ParseError> {
    let length = count as usize;
    if i.len() < length {
        Incomplete(Needed::Size(length))
    } else {
        Done(&i[length..], &i[..length])
    }
}
