use crate::{
    quic::QuicStream,
    socks::{AuthMethods, InitReply, InitReq, SOCKS_VERSION},
};
use bytes::BytesMut;
use log::*;
use quinn::{
    crypto::rustls::TlsSession,
    generic::{Connection, Endpoint},
    transport::Socket,
    ClientConfig, ClientConfigBuilder, ReadError, TransportConfig,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::RwLock,
};

/// Dummy certificate verifier that treats any certificate as valid.
/// NOTE, such verification is vulnerable to MITM attacks, but convenient for testing.
struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _roots: &rustls::RootCertStore,
        _presented_certs: &[rustls::Certificate],
        _dns_name: webpki::DNSNameRef,
        _ocsp_response: &[u8],
    ) -> Result<rustls::ServerCertVerified, rustls::TLSError> {
        Ok(rustls::ServerCertVerified::assertion())
    }
}

// Configure the ALPN and allow *ANY* cert without looking at *ANY* properties.
fn configure_client() -> ClientConfig {
    let mut cfg = ClientConfigBuilder::default();
    cfg.protocols(crate::ALPN_QUIC);
    let mut cfg = cfg.build();

    let tls_cfg: &mut rustls::ClientConfig = Arc::get_mut(&mut cfg.crypto).unwrap();
    tls_cfg.enable_sni = false;
    // this is only available when compiled with "dangerous_configuration" feature
    tls_cfg
        .dangerous()
        .set_certificate_verifier(SkipServerVerification::new());
    cfg
}

// These fields are public,
// Per Rust By Example:
// This visibility only matters when a struct is accessed from outside the module where it is defined, and has the goal of hiding information (encapsulation).
pub struct Client<T: Socket> {
    conn: Arc<RwLock<Connection<TlsSession, T>>>,
    tcp: TcpListener,
    endpoint: Endpoint<TlsSession, T>,
    remote: SocketAddr,
    hostname: Arc<str>,
}

impl<T: Socket> Client<T> {
    pub async fn init(
        remote: SocketAddr,
        bind: SocketAddr,
        socket: T,
        hostname: &str,
    ) -> anyhow::Result<Self> {
        // We send keep-alive-package to keep the connection alive!
        let mut transport_cfg = TransportConfig::default();
        transport_cfg.keep_alive_interval(Some(Duration::from_secs(30)));
        transport_cfg.max_idle_timeout(Some(std::time::Duration::from_secs(180)))?;

        let mut client_cfg = configure_client();
        client_cfg.transport = Arc::new(transport_cfg);
        let mut endpoint_builder = Endpoint::<TlsSession, T>::builder();
        endpoint_builder.default_client_config(client_cfg);

        let (endpoint, _) = endpoint_builder.with_socket(socket)?;

        // connect to remote
        let new_conn: quinn::generic::NewConnection<TlsSession, T> =
            endpoint.connect(&remote, hostname)?.await?;

        Ok(Self {
            conn: Arc::new(RwLock::new(new_conn.connection)),
            tcp: TcpListener::bind(bind).await?,
            endpoint,
            remote,
            hostname: hostname.into(),
        })
    }

    // Allow reconnection
    pub async fn connect(&self) -> anyhow::Result<()> {
        let new_conn: quinn::generic::NewConnection<TlsSession, T> =
            self.endpoint.connect(&self.remote, &self.hostname)?.await?;
        let mut conn_mut = self.conn.write().await;
        *conn_mut = new_conn.connection;
        Ok(())
    }
}

// TODO: Can we find a better pattern? wrapping it around Arc seems awkward.
pub async fn run<T: Socket>(client: Arc<Client<T>>) -> anyhow::Result<()> {
    while let Ok((stream, addr)) = client.tcp.accept().await {
        info!("TCP connection accepted from {}", addr);
        tokio::spawn(handle_stream(stream, client.clone()));
    }
    Ok(())
}

// Handle a single TCP stream from the requestor
async fn handle_stream<T: Socket>(
    mut stream: TcpStream,
    client: Arc<Client<T>>,
) -> anyhow::Result<()> {
    match InitReq::read(&mut stream).await? {
        InitReq { version, mtds }
            if (version == SOCKS_VERSION) && mtds.contains(&AuthMethods::NoAuth) =>
        {
            info!("using no auth method");
            let mut msg: BytesMut = InitReply::method(AuthMethods::NoAuth).into();
            stream.write_all(&mut msg).await?
        }
        _ => {
            warn!("unsupported SOCKS auth method or version");
            let mut msg: BytesMut = InitReply::no_method().into();
            stream.write_all(&mut msg).await?;
            return Err(anyhow::anyhow!("unsupported SOCKS auth method or version"));
        }
    };

    info!("creating new bidi stream to the remote");
    let (send, recv) = client.conn.read().await.open_bi().await?;
    let mut quic_stream = QuicStream::new(recv, send);
    info!("stream created successfully");

    match tokio::io::copy_bidirectional(&mut stream, &mut quic_stream).await {
        Err(e) => {
            warn!("bidi copy exited with error: {}", e);
            match e.get_ref().and_then(|x| x.downcast_ref::<ReadError>()) {
                Some(ReadError::ConnectionClosed(_)) => {
                    info!("connection errored, trying to reconnet");
                    match client.connect().await {
                        Ok(()) => {
                            info!("reconnected successfully.");
                        }
                        Err(e) => {
                            warn!("failed to reconnect: {}", e);
                        }
                    };
                }
                _ => {
                    // Not connection related errors or not even QUIC's fault. We don't have to recreate the connection.
                }
            };
        }
        Ok((tx, rx)) => info!("bidi copy finished. tx: {}, rx: {}", tx, rx),
    };

    info!("requestor closed");

    Ok(())
}
