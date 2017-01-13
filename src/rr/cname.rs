use ::names::Name;
use ::rr::{Type, Class, ResourceRecord};

/// The canonical name for an alias
#[derive(Debug,Clone)]
pub struct CNAME {
    name: Name,
    class: Class,
    ttl: i32,
    data: Name
}
resource_record_impl!(CNAME, CNAMEType, "CNAME", 5, Name);

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
