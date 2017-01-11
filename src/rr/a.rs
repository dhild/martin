use ::names::Name;
use ::rr::*;
use std::net::Ipv4Addr;

/// A host address resource record
#[derive(Debug,Clone)]
pub struct A {
    name: Name,
    class: Class,
    ttl: i32,
    addr: Ipv4Addr,
}

/// The `A` type has a value of `1`
#[derive(Debug,Clone,Copy)]
pub struct AType;

impl Type for AType {
    fn name(&self) -> &str {
        "A"
    }
    fn value(&self) -> u16 {
        1
    }
}

impl ResourceRecord for A {
    type RRType = AType;
    type DataType = Ipv4Addr;
    fn name(&self) -> &Name {
        &self.name
    }
    fn rr_type(&self) -> AType {
        AType {}
    }
    fn rr_class(&self) -> &Class {
        &self.class
    }
    fn ttl(&self) -> i32 {
        self.ttl
    }

    fn data(&self) -> &Ipv4Addr {
        &self.addr
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
