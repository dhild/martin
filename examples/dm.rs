/// `dm` is a simple utility to issue DNS requests and output the responses.
/// The concept is similar to a simplified `dig` BIND utility.
extern crate martin;
extern crate getopts;
#[macro_use]
extern crate log;
extern crate log4rs;

#[cfg(windows)]
extern crate winreg;

use getopts::{Options, Matches, HasArg, Occur};
use log4rs::Handle;
use martin::{QType, Class};
use std::env;
use std::net::*;

fn debug_wait() {
    use std::io;

    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("error while reading stdin");
}

pub fn main() {
    debug_wait();
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    let mut opts = Options::new();
    opts.optopt("c", "", "Class to query", "class");
    opts.optopt("t", "", "Type to query", "type");
    opts.optopt("p", "", "The port number to send queries to.", "port");
    opts.optflag("h", "help", "Print this help menu");
    opts.opt("v",
             "verbose",
             "Output verbose logging (use -vv or -vvv for more verbose)",
             "",
             HasArg::No,
             Occur::Multi);
    let matches = match opts.parse(&args[1..]) {
        Ok(m) => m,
        Err(e) => {
            println!("Unable to parse arguments: {}", e);
            return;
        }
    };
    if matches.opt_present("h") {
        print_usage(&program, opts);
        return;
    }
    setup_logging(&matches);

    let config = match Config::new(matches) {
        Ok(c) => c,
        Err(e) => {
            print_usage(&program, opts);
            println!("\nError: {:?}", e);
            return;
        }
    };

    run_query(config);
}

fn serialize_query(config: &Config) -> Vec<u8> {
    use martin::{Message, Question, WriteError};
    use std::io::Cursor;

    let question = Question::new(&config.name, config.qtype, config.class).unwrap();
    let msg = Message::query(0xaaaa, true, &[question]);

    let mut data: [u8; 20] = [0; 20];
    let mut cursor = Cursor::new(&mut data[..]);
    if let Err(e) = msg.write(&mut cursor) {
        match e {
            WriteError::Truncated => {}
            _ => panic!("Unexpected failure! {}", e),
        }
    }
    cursor.into_inner().to_vec()
}

fn run_query(config: Config) {
    use std::net::UdpSocket;
    use std::time::Duration;

    let socket = UdpSocket::bind(("127.0.0.1", 0)).expect("Could not bind to socket");
    debug!("udp socket on: {}", socket.local_addr().unwrap());
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .expect("Could not set write timeout");
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("Could not set read timeout");

    let buf = serialize_query(&config);
    socket
        .send_to(&buf, (config.servers[0], 53))
        .expect("Could not send packet");
    trace!("Sent UDP packet (size {}) to {}",
           buf.len(),
           config.servers[0]);
    let mut buf = [0; 4096];
    let (count, src) = socket
        .recv_from(&mut buf)
        .expect("Could not recieve data");
    trace!("Recieved UDP packet of size {} from {}", count, src);
}

fn print_usage(program: &str, opts: Options) {
    let brief = format!("Usage: {} [@server] [name] [options]", program);
    print!("{}", opts.usage(&brief));
}

fn setup_logging(matches: &Matches) -> Handle {
    use log::LogLevelFilter;
    use log4rs::append::console::ConsoleAppender;
    use log4rs::encode::pattern::PatternEncoder;
    use log4rs::config::{Appender, Config, Root};
    let root_level = match matches.opt_count("v") {
        0 => LogLevelFilter::Warn,
        1 => LogLevelFilter::Info,
        2 => LogLevelFilter::Debug,
        _ => LogLevelFilter::Trace,
    };
    let pattern = match root_level {
        LogLevelFilter::Warn => PatternEncoder::new("{m}{n}"),
        LogLevelFilter::Info => PatternEncoder::new("{l} {M} - {m}{n}"),
        _ => PatternEncoder::new("{d} {M} [{T}] {l} - {m}{n}"),
    };
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(pattern))
        .build();
    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(Root::builder().appender("stdout").build(root_level))
        .unwrap();

    log4rs::init_config(config).unwrap()
}

struct Config {
    servers: Vec<IpAddr>,
    name: String,
    qtype: QType,
    class: Class,
}

#[derive(Debug)]
enum ConfigError {
    AddrError(AddrParseError),
    MissingName,
}

impl From<AddrParseError> for ConfigError {
    fn from(e: AddrParseError) -> ConfigError {
        ConfigError::AddrError(e)
    }
}

impl Config {
    fn new(matches: Matches) -> Result<Config, ConfigError> {
        let servers = try!(find_servers(&matches));
        if log_enabled!(log::LogLevel::Info) {
            let ns: String = servers
                .iter()
                .map(|a| -> String { format!("{} ", a) })
                .collect();
            info!("Using name servers: [{}]", ns);
        }
        let name: String = match matches
                  .free
                  .iter()
                  .filter(|s| !s.starts_with("@"))
                  .next() {
            Some(s) => s.clone(),
            None => return Err(ConfigError::MissingName),
        };
        Ok(Config {
               servers: servers,
               name: name,
               qtype: QType::Any,
               class: Class::Internet,
           })
    }
}

const DNS_KEY: &'static str = r#"System\CurrentControlSet\Services\Tcpip\Parameters"#;
const OPEN_DNS_ADDRS: &'static str = "208.67.222.222 208.67.220.220 2620:0:ccc::2 2620:0:ccd::2";

fn find_servers(matches: &Matches) -> Result<Vec<IpAddr>, ConfigError> {
    if let Some(s) = matches
           .free
           .iter()
           .filter(|s| s.starts_with("@"))
           .map(|s| -> String { s.chars().skip(1).collect() })
           .next() {
        let addr: IpAddr = try!(s.parse());
        return Ok(vec![addr]);
    }
    if let Some(addrs) = find_servers_os_specific() {
        return Ok(addrs);
    }
    Ok(OPEN_DNS_ADDRS
           .split_whitespace()
           .filter_map(|s| s.parse().ok())
           .collect())
}

#[cfg(not(windows))]
fn find_servers_os_specific() -> Option<Vec<IpAddr>> {
    Some(Vec::new())
}

#[cfg(windows)]
fn find_servers_os_specific() -> Option<Vec<IpAddr>> {
    use std::io;
    use winreg::enums::{HKEY_LOCAL_MACHINE, KEY_READ};
    let hklm = winreg::RegKey::predef(HKEY_LOCAL_MACHINE);
    if let Ok(nskey) = hklm.open_subkey_with_flags(DNS_KEY, KEY_READ) {
        let value: io::Result<String> = nskey.get_value("NameServer");
        if let Ok(ns) = value {
            let addrs: Vec<IpAddr> = ns.split_whitespace()
                .filter_map(|s| s.parse().ok())
                .collect();
            if addrs.len() > 0 {
                return Some(addrs);
            }
        }
    }
    None
}
