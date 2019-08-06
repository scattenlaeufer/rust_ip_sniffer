extern crate argparse;

use argparse::{ArgumentParser, Store};
use std::io::{self, Write};
use std::net::{IpAddr, TcpStream};
use std::process;
use std::str::FromStr;
use std::sync::mpsc::{channel, Sender};
use std::thread;

const MAX: u16 = 65535;

#[derive(Debug)]
struct Arguments {
    flag: String,
    ipaddr: IpAddr,
    threads: u16,
}

impl Arguments {
    fn new(ipaddr: &String, threads: &u16) -> Result<Arguments, &'static str> {
        let ipaddr = match IpAddr::from_str(&ipaddr) {
            Ok(addr) => addr,
            Err(_) => return Err("Not a valid IPADDR; must be IPv4 or IPv6"),
        };
        return Ok(Arguments {
            flag: String::from(""),
            ipaddr,
            threads: *threads,
        });
    }
}

fn scan(tx: Sender<u16>, start_port: u16, addr: IpAddr, num_threads: u16) {
    let mut port: u16 = start_port + 1;
    loop {
        match TcpStream::connect((addr, port)) {
            Ok(_) => {
                print!(".");
                io::stdout().flush().unwrap();
                tx.send(port).unwrap();
            }
            Err(_) => {}
        }
        if (MAX - port) <= num_threads {
            break;
        }
        port += num_threads;
    }
}

fn main() {
    let mut ipaddr = "".to_string();
    let mut threads: u16 = 4;
    {
        let mut ap = ArgumentParser::new();
        ap.set_description("A small ip sniffer written in Rust.");
        ap.refer(&mut threads)
            .add_option(&["-j", "--threads"], Store, "Number of threads to run");
        ap.refer(&mut ipaddr)
            .add_argument("IPADDR", Store, "IP address to sniff")
            .required();
        ap.parse_args_or_exit();
    }
    let arguments = Arguments::new(&ipaddr, &threads).unwrap_or_else(|err| {
        println!("{}", err);
        process::exit(0);
    });

    let num_threads = arguments.threads;
    let addr = arguments.ipaddr;
    let (tx, rx) = channel();
    for i in 0..num_threads {
        let tx = tx.clone();

        thread::spawn(move || {
            scan(tx, i, addr, num_threads);
        });
    }

    drop(tx);
    let mut out = vec![];
    for p in rx {
        out.push(p);
    }
    println!("");
    out.sort();
    for v in out {
        println!("{} is open", v);
    }
}
