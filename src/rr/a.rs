use ::names::Name;
use ::rr::{Type, Class, ResourceRecord};
use std::net::Ipv4Addr;

/// An IPv4 host address resource record
#[derive(Debug,Clone)]
pub struct A {
    name: Name,
    class: Class,
    ttl: i32,
    data: Ipv4Addr
}

impl ResourceRecord for A {
    fn name(&self) -> &Name {
        &self.name
    }
    fn rr_type(&self) -> Type {
        Type::A
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
