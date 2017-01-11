use ::names::Name;
use ::rr::{Type, Class, ResourceRecord};

/// The canonical name for an alias
#[derive(Debug,Clone)]
pub struct CNAME {
    name: Name,
    class: Class,
    ttl: i32,
    cname: Name,
}

/// The `CNAME` type has a value of `5`
#[derive(Debug,Clone,Copy)]
pub struct CNAMEType;

impl Type for CNAMEType {
    fn name(&self) -> &str {
        "CNAME"
    }
    fn value(&self) -> u16 {
        5
    }
}

impl ResourceRecord for CNAME {
    type RRType = CNAMEType;
    type DataType = Name;
    fn name(&self) -> &Name {
        &self.name
    }
    fn rr_type(&self) -> CNAMEType {
        CNAMEType {}
    }
    fn rr_class(&self) -> &Class {
        &self.class
    }
    fn ttl(&self) -> i32 {
        self.ttl
    }

    fn data(&self) -> &Name {
        &self.cname
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
