enum Type {
    A,
    NS,
    CNAME,
    SOA,
    MX,
    TXT
}

enum Class {
    IN,
    CH
}

trait ResourceRecord {
    fn name(&self) -> &str;
    fn type(&self) -> Type;
    fn class(&self) -> Class;
    fn ttl(&self) -> i32;
    fn rdlength(&self) -> i16;
    fn rdata(&self) -> &[u8];
}
