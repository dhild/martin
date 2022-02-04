use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6, UdpSocket};
use thiserror::Error;
use crate::header::{Rcode};
use crate::message::Message;
use crate::names::NameParseError;
use crate::question::{QType, Question};
use crate::rr::{ResourceRecord, Type};

const MAX_LOOKUPS: usize = 20;

pub fn resolve(host: &str) -> Result<Vec<IpAddr>, ResolveError> {
    let mut nameserver = IpAddr::V4(Ipv4Addr::new(198, 41, 0, 4));
    for _ in 0..MAX_LOOKUPS {
        println!("Querying {nameserver}: {host}");
        let reply = dns_query(host, &nameserver)?;
        println!("{reply}");
        // Preferred case: we get a "doesn't exist" response, or an answer
        if reply.authoritative() && reply.header.rcode == Rcode::NameError {
            return Err(ResolveError::NoSuchDomain);
        }
        if let Some(addrs) = get_answer(&reply) {
            return Ok(addrs);
        }
        if let Some(glue) = get_glue(&reply) {
            // Second best: we received the IP of another nameserver to query
            nameserver = glue;
        } else if let Some(ns) = get_ns(&reply) {
            // Third best: we received the domain name of another nameserver to query
            nameserver = resolve(&ns)
                .map_err(|e| ResolveError::RecursiveLookupFailed(e.into()))?
                .first()
                .cloned()
                .expect("No results is returned as an error");
        }
    }
    Err(ResolveError::ExceededMaximumLookupDepth(MAX_LOOKUPS))
}

#[derive(Debug, Error)]
pub enum ResolveError {
    #[error("query exceeded the maximum lookup depth ({0})")]
    ExceededMaximumLookupDepth(usize),

    #[error("domain name could not be resolved")]
    NoSuchDomain,

    #[error("domain name required a recursive lookup, which failed. {0}")]
    RecursiveLookupFailed(#[from]Box<ResolveError>),

    #[error("IO error: {0}")]
    IOError(#[from] std::io::Error),

    #[error("host name is not a valid domain name. {0}")]
    InvalidHost(#[from] NameParseError),

    #[error("deserialization error: {0}")]
    DeseralizationFailed(#[from] nom::Err<nom::error::Error<Vec<u8>>>),
}

fn dns_query(host: &str, nameserver: &IpAddr) -> Result<Message, ResolveError> {
    let (socket, addr): (_,SocketAddr) = match nameserver {
        IpAddr::V4(addr) => (UdpSocket::bind("0.0.0.0:0")?, SocketAddrV4::new(*addr, 53).into()),
        IpAddr::V6(addr) => (UdpSocket::bind("[::]:0")?, SocketAddrV6::new(*addr, 53, 0, 0).into()),
    };
    socket.connect(addr)?;

    let question = Question::new(host, QType::ByType(Type::A))?;
    let msg = Message::query(1, false, question).encode();
    socket.send(&msg)?;

    let mut buf = [0u8;512];
    let size = socket.recv(buf.as_mut_slice())?;
    Ok(Message::decode(&buf[0..size])?)
}

fn get_answer(msg: &Message) -> Option<Vec<IpAddr>> {
    if msg.answers.len() == 0 {
        return None;
    }
    msg.answers.iter()
        .filter_map(|rr| match rr {
            ResourceRecord::A { addr, .. } => Some(IpAddr::V4(*addr)),
            ResourceRecord::AAAA { addr, .. } => Some(IpAddr::V6(*addr)),
            _ => None,
        })
        .collect::<Vec<IpAddr>>()
        .into()
}

fn get_glue(msg: &Message) -> Option<IpAddr> {
    msg.additionals.iter()
        .find_map(|rr| match rr {
            ResourceRecord::A { addr, .. } => Some(IpAddr::V4(*addr)),
            ResourceRecord::AAAA { addr, .. } => Some(IpAddr::V6(*addr)),
            _ => None,
        })
}

fn get_ns(msg: &Message) -> Option<String> {
    msg.authorities.iter()
        .find_map(|rr| match rr {
            ResourceRecord::NS { ns_name, .. } => Some(ns_name.to_string()),
            _ => None,
        })
}