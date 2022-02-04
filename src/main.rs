use clap::Parser;
use martin::resolve;

/// DNS resolver implementation
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    host: Option<String>,
}

fn main() {
    let args = Args::parse();

    if let Some(host) = args.host {
        println!("Name: {host}\n");
        let host = if host.ends_with(".") {
            host
        } else {
            format!("{host}.")
        };
        match resolve(&host) {
            Ok(addresses) => match addresses.len() {
                0 => println!("No address records"),
                1 => println!("Address: {}", addresses[0]),
                _ => {
                    println!("Addresses: {}", addresses[0]);
                    for addr in &addresses[1..] {
                        println!("           {addr}");
                    }
                }
            },
            Err(e) => eprintln!("Failed to query DNS: {e}"),
        }
    }
}
