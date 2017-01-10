
use ::names::Name;
use ::rr::*;
use std::net::Ipv4Addr;

#[derive(Debug)]
pub struct ARecord {
    name: Name,
    rrclass: RecordClass,
    ttl: i32,
    addr: Ipv4Addr,
}

#[derive(Debug)]
pub struct ARecordType;

impl RecordType for ARecordType {
    fn name(&self) -> &str {
        "A"
    }
    fn value(&self) -> u16 {
        1
    }
}

impl ResourceRecord for ARecord {
    type RType = ARecordType;
    type DType = Ipv4Addr;
    fn name(&self) -> &Name {
        &self.name
    }
    fn rr_type(&self) -> ARecordType {
        ARecordType {}
    }
    fn rr_class(&self) -> &RecordClass {
        &self.rrclass
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
