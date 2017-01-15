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

impl ResourceRecord for CNAME {
    fn name(&self) -> &Name {
        &self.name
    }
    fn rr_type(&self) -> Type {
        Type::CNAME
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
