use super::names::Name;
use super::rr::Class;

#[derive(Debug,Clone)]
pub struct Question {
    qname: Name,
    qtype: i32,
    qclass: Class,
}
