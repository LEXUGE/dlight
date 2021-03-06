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
    SimpleLogger::new().with_level(LevelFilter::Debug).init()?;
    if let Some(remote) = args.remote {
        // We bind to 0 port to get a random available port. Note "0.0.0.0" is necessary to communicate with the outer internet!
        // Else it results in quite confusing LocallyClosed error.
        // The reason behind is that the ConnectionDriver exits when EndpointDriver exits when transport poll_send fails because
        // we are listening on loopback instead of 0.0.0.0!
        let udp = std::net::UdpSocket::bind("0.0.0.0:0")?;
        let client: std::sync::Arc<Client<DnsSocket>> = std::sync::Arc::new(
            Client::init(remote, args.bind, udp.try_into()?, &args.hostname).await?,
        );
        client::run(client).await?;
    } else {
        let udp = std::net::UdpSocket::bind(args.bind)?;
        let mut server: Server<DnsSocket> = Server::new(udp.try_into()?)?;
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

    #[structopt(short, long, parse(try_from_str = str::parse), default_value = "localhost")]
    hostname: String,
}
