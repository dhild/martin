use std::fmt;
use super::names::Name;

pub trait RecordType {
    fn name(&self) -> &str;
    fn value(&self) -> u16;
}

#[derive(Debug,PartialEq,Clone,Copy)]
pub enum RecordClass {
    IN,
}

pub trait ResourceRecord {
    type RType: RecordType;
    type DType;

    fn name(&self) -> &Name;
    fn rr_type(&self) -> Self::RType;
    fn rr_class(&self) -> &RecordClass;
    fn ttl(&self) -> i32;

    fn data(&self) -> &Self::DType;
}

impl fmt::Display for RecordClass {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            RecordClass::IN => write!(f, "IN"),
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
