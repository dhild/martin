//! A Rust library for DNS requests, answers, and resolving.

mod resolve;
pub mod message;
pub mod rr;
pub mod names;
mod header;
mod question;

pub use resolve::resolve;
pub use message::Message;
pub use rr::ResourceRecord;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
