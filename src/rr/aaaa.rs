use ::names::Name;
use ::rr::{Type, Class, ResourceRecord};
use std::net::Ipv6Addr;

/// An IPv6 host address resource record
#[derive(Debug,Clone)]
pub struct AAAA {
    name: Name,
    class: Class,
    ttl: i32,
    data: Ipv6Addr
}

impl ResourceRecord for AAAA {
    fn name(&self) -> &Name {
        &self.name
    }
    fn rr_type(&self) -> Type {
        Type::AAAA
    }
    fn rr_class(&self) -> Class {
        self.class
    }
    fn ttl(&self) -> i32 {
        self.ttl
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
