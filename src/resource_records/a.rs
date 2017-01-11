
use ::names::Name;
use ::rr::*;
use std::net::Ipv4Addr;

#[derive(Debug)]
pub struct ARecord {
    name: Name,
    class: Class,
    ttl: i32,
    addr: Ipv4Addr,
}

#[derive(Debug)]
pub struct AType;

impl Type for AType {
    fn name(&self) -> &str {
        "A"
    }
    fn value(&self) -> u16 {
        1
    }
}

impl ResourceRecord for ARecord {
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
