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
resource_record_impl!(AAAA, AAAAType, "AAAA", 1, Ipv6Addr);

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
