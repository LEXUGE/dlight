use crate::{
    quic::QuicStream,
    socks::{CmdReply, CmdRequest, Command, RespCode, SOCKS_VERSION},
};
use bytes::BytesMut;
use futures::StreamExt;
use log::*;
use quinn::{
    crypto::rustls::TlsSession, generic::Incoming, transport::Socket, CertificateChain, PrivateKey,
    TransportConfig,
};
use rcgen::generate_simple_self_signed;
use tokio::{io::AsyncWriteExt, net::TcpStream};

pub struct Server<T: Socket> {
    incoming: Incoming<TlsSession, T>,
}

impl<T: Socket> Server<T> {
    pub fn new(socket: T) -> anyhow::Result<Self> {
        // Generate a certificate that's valid for "localhost"
        // We are having trouble with IP signed root CA
        let subject_alt_names = vec!["localhost".to_string(), "a.cn".to_string()];
        let cert = generate_simple_self_signed(subject_alt_names).unwrap();

        let cert_chain = CertificateChain::from_pem(&cert.serialize_pem()?.into_bytes())?;
        let priv_key = PrivateKey::from_pem(&cert.serialize_private_key_pem().into_bytes())?;

        let mut servercfg = quinn::generic::ServerConfigBuilder::default();
        servercfg.protocols(crate::ALPN_QUIC);
        servercfg.certificate(cert_chain, priv_key)?;

        // Set up the server config
        let mut servercfg = servercfg.build();

        let mut transport_cfg = TransportConfig::default();
        transport_cfg.max_idle_timeout(Some(std::time::Duration::from_secs(180)))?;

        servercfg.transport = std::sync::Arc::new(transport_cfg);

        let mut endpt_cfg = quinn::generic::Endpoint::<TlsSession, T>::builder();
        endpt_cfg.listen(servercfg);
        let (_, incoming) = endpt_cfg.with_socket(socket)?;

        Ok(Self { incoming })
    }

    pub async fn serve(&mut self) -> anyhow::Result<()> {
        while let Some(connecting) = self.incoming.next().await {
            info!("connecting from remote: {:?}", connecting.remote_address());

            // TODO: will this be throttling when connecting.
            match connecting.await {
                Ok(mut conn) => {
                    info!(
                        "connection established from remote: {:?}",
                        conn.connection.remote_address()
                    );
                    // We spawn to create handle each bidi stream.
                    tokio::spawn(async move {
                        while let Some(x) = conn.bi_streams.next().await {
                            match x {
                                Ok((send, recv)) => {
                                    tokio::spawn(handle_bidi(QuicStream::new(recv, send)));
                                }
                                Err(e) => {
                                    warn!("a connection error occured: {}", e);
                                    return;
                                }
                            }
                        }
                    });
                }
                Err(e) => {
                    warn!("connection failed to establish: {}", e);
                }
            }
        }
        Ok(())
    }
}

async fn handle_bidi<T: Socket>(mut stream: QuicStream<T>) -> anyhow::Result<()> {
    // Authentication and methods selection have already been done on the "client" side of the QUIC connection, we only care about method.
    match CmdRequest::read(&mut stream).await? {
        CmdRequest {
            version,
            command,
            addr,
        } if version == SOCKS_VERSION && command == Command::Connect => {
            match TcpStream::connect(addr.addr).await {
                Ok(mut v) => {
                    // We successfully established the connection to remote, now we send back reply with confirmation
                    info!("successfully established connection to remote");
                    let msg: BytesMut = CmdReply::success(addr.into()).into();
                    stream.write_all(&msg).await?;
                    tokio::io::copy_bidirectional(&mut stream, &mut v)
                        .await
                        .unwrap();

                    info!("client closed stream");
                }
                Err(_) => {
                    warn!("failed to connect to remote host via TCP, replying the client with a connection failure");
                    let msg: BytesMut = CmdReply::failure(RespCode::GeneralFailure).into();
                    stream.write_all(&msg).await?;
                    return Err(anyhow::anyhow!(
                        "failed to connect to the remote host via TCP"
                    ));
                }
            }
        }
        _ => {
            warn!("unsupported SOCKS protocol version or command, replying with a failure msg");
            let msg: BytesMut = CmdReply::failure(RespCode::GeneralFailure).into();
            stream.write_all(&msg).await?;
            return Err(anyhow::anyhow!(
                "unsupported SOCKS protocol version or command"
            ));
        }
    };
    Ok(())
}
