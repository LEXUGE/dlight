mod client;
mod quic;
mod server;
mod socks;
mod transport;

use crate::{client::Client, server::Server, transport::DnsSocket};
use anyhow::Result;
use log::*;
use simple_logger::SimpleLogger;
use std::{convert::TryInto, net::SocketAddr};
use structopt::StructOpt;

pub const ALPN_QUIC: &[&[u8]] = &[b"hq-29"];

#[tokio::main]
async fn main() -> Result<()> {
    let args: DlightOpts = DlightOpts::from_args();
    SimpleLogger::new().with_level(LevelFilter::Trace).init()?;
    if let Some(remote) = args.remote {
        // TODO: How to bind client quic?
        let udp = std::net::UdpSocket::bind("127.0.0.1:45678")?;
        let mut client = Client::<DnsSocket>::init(remote, args.bind, udp.try_into()?).await?;
        client.run().await?;
    } else {
        let udp = std::net::UdpSocket::bind(args.bind)?;
        let mut server = Server::<DnsSocket>::new(udp.try_into()?)?;
        server.serve().await?;
    }
    Ok(())
}

#[derive(Debug, StructOpt)]
#[structopt(name = "dlight", about = "A DNS-tunnel proxy using KCP")]
struct DlightOpts {
    #[structopt(short, long, parse(try_from_str = str::parse))]
    bind: SocketAddr,

    #[structopt(short, long, parse(try_from_str = str::parse))]
    remote: Option<SocketAddr>,
}
