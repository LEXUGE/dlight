use crate::{
    quic::QuinnStream,
    socks::{AuthMethods, InitReply, InitReq, SOCKS_VERSION},
};
use bytes::BytesMut;
use log::*;
use quinn::{
    crypto::rustls::TlsSession, generic::Endpoint, transport::Socket, ClientConfig,
    ClientConfigBuilder, Connection,
};
use std::{marker::PhantomData, net::SocketAddr, sync::Arc};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
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

pub struct Client<T: Socket> {
    quic: Connection,
    tcp: TcpListener,
    socket_type: PhantomData<T>,
}

impl<T: Socket> Client<T> {
    pub async fn init(remote: SocketAddr, bind: SocketAddr, socket: T) -> anyhow::Result<Self> {
        let client_cfg = configure_client();
        let mut endpoint_builder = Endpoint::<TlsSession, T>::builder();
        endpoint_builder.default_client_config(client_cfg);

        let (endpoint, _) = endpoint_builder.with_socket(socket)?;

        // connect to remote
        let quinn::NewConnection { connection, .. } =
            endpoint.connect(&remote, "localhost")?.await?;

        Ok(Self {
            quic: connection,
            tcp: TcpListener::bind(bind).await?,
            socket_type: PhantomData,
        })
    }

    pub async fn run(&mut self) -> anyhow::Result<()> {
        while let Ok((stream, addr)) = self.tcp.accept().await {
            info!("TCP connection accepted from {}", addr);
            tokio::spawn(handle_stream(self.quic.clone(), stream));
        }
        Ok(())
    }
}

// Handle a single TCP stream from the requestor
async fn handle_stream(quic: Connection, mut stream: TcpStream) -> anyhow::Result<()> {
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
    let (send, recv) = quic.open_bi().await?;
    let mut quic_stream = QuinnStream::new(recv, send);
    info!("stream created successfully");

    tokio::io::copy_bidirectional(&mut stream, &mut quic_stream).await?;

    info!("requestor closed");

    Ok(())
}
