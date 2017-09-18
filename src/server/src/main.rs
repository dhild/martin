//! A DNS server
#![doc(html_root_url = "https://dhild.github.io/martin/")]
#![deny(missing_docs,
        missing_debug_implementations, missing_copy_implementations,
        trivial_casts,
        unsafe_code,
        unstable_features,
        unused_import_braces, unused_qualifications)]
#![cfg_attr(feature = "clippy", feature(plugin))]
#![cfg_attr(feature = "clippy", plugin(clippy))]

#[macro_use]
extern crate log;
extern crate log4rs;

use log4rs::Handle;
use std::env;

pub fn main() {
    let args: Vec<String> = env::args().collect();
    let program = args[0].clone();
    setup_logging();

    run_server_loop();

    info!("Exiting {}", program);
}

fn setup_logging() -> Handle {
    use log::LogLevelFilter;
    use log4rs::append::console::ConsoleAppender;
    use log4rs::encode::pattern::PatternEncoder;
    use log4rs::config::{Appender, Config, Root};
    let root_level = LogLevelFilter::Debug;
    let pattern = PatternEncoder::new("{d} {M} [{T}] {l} - {m}{n}");
    let stdout = ConsoleAppender::builder()
        .encoder(Box::new(pattern))
        .build();
    let config = Config::builder()
        .appender(Appender::builder().build("stdout", Box::new(stdout)))
        .build(Root::builder().appender("stdout").build(root_level))
        .unwrap();

    log4rs::init_config(config).unwrap()
}

fn run_server_loop() {}

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {}
}
