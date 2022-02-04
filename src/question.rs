use byteorder::{BigEndian, WriteBytesExt};
use crate::names::{Name, NameParseError};
use crate::rr::{Class, Type};
use std::convert::From;
use std::io;
use std::io::{Cursor, Write};

/// The scope of query to execute.
#[derive(Debug,Clone,PartialEq,Copy)]
pub enum QType {
    /// The type of record being queried.
    ByType(Type),
    /// A query requesting all records for a name.
    Any,
}

/// Describes a DNS query.
#[derive(Debug,Clone,PartialEq)]
pub struct Question {
    pub qname: Name,
    pub qtype: QType,
    pub qclass: Class,
}

impl Question {
    /// Create a `Question`.
    pub fn new(qname: &str, qtype: QType) -> Result<Question, NameParseError> {
        qname.parse().map(|name: Name| {
            Question {
                qname: name,
                qtype,
                qclass: Class::Internet,
            }
        })
    }
    pub fn write_to<T>(&self, cursor: &mut Cursor<T>) -> io::Result<()> where Cursor<T>: Write {
        self.qname.write_to(cursor)?;
        cursor.write_u16::<BigEndian>(self.qtype.into())?;
        cursor.write_u16::<BigEndian>(self.qclass.into())?;
        Ok(())
    }

}

impl From<u16> for QType {
    fn from(value: u16) -> QType {
        match Type::from(value) {
            Type::Unknown { value: 255 } => QType::Any,
            t => QType::ByType(t),
        }
    }
}

impl From<QType> for u16 {
    fn from(value: QType) -> u16 {
        match value {
            QType::Any => 255,
            QType::ByType(t) => t.into(),
        }
    }
}
