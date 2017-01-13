use ::names::Name;
use ::rr::{Type, Class, ResourceRecord};
use std::net::Ipv4Addr;

/// A host address resource record
#[derive(Debug,Clone)]
pub struct A {
    name: Name,
    class: Class,
    ttl: i32,
    data: Ipv4Addr
}
resource_record_impl!(A, AType, "A", 1, Ipv4Addr);

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
