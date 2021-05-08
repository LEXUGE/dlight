use quinn::transport::RecvMeta;
use std::{
    convert::TryFrom,
    io,
    net::SocketAddr,
    task::{Context, Poll},
};

// `Socket` trait implementations for quinn
use quinn::transport::Socket;
use tokio::io::ReadBuf;
use trust_dns_proto::{
    op::message::Message,
    rr::{rdata::null::NULL, record_data::RData, resource::Record, Name},
    serialize::binary::BinEncodable,
};

pub struct DnsSocket {
    io: tokio::net::UdpSocket,
}

impl TryFrom<std::net::UdpSocket> for DnsSocket {
    type Error = io::Error;

    fn try_from(socket: std::net::UdpSocket) -> Result<Self, Self::Error> {
        socket.set_nonblocking(true)?;
        Ok(DnsSocket {
            io: tokio::net::UdpSocket::from_std(socket)?,
        })
    }
}

impl Socket for DnsSocket {
    fn poll_send(
        &self,
        cx: &mut Context,
        transmits: &mut [quinn::Transmit],
    ) -> Poll<Result<usize, io::Error>> {
        let mut sent = 0;
        for transmit in transmits {
            encode(&mut transmit.contents)?;
            match self
                .io
                .poll_send_to(cx, &transmit.contents, transmit.destination)
            {
                Poll::Ready(Ok(_)) => {
                    sent += 1;
                }
                // We need to report that some packets were sent in this case, so we rely on
                // errors being either harmlessly transient (in the case of WouldBlock) or
                // recurring on the next call.
                Poll::Ready(Err(_)) | Poll::Pending if sent != 0 => return Poll::Ready(Ok(sent)),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(sent))
    }

    fn poll_recv(
        &self,
        cx: &mut Context,
        bufs: &mut [io::IoSliceMut<'_>],
        meta: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        debug_assert!(!bufs.is_empty());
        let mut buf = ReadBuf::new(&mut bufs[0]);
        let addr = futures::ready!(self.io.poll_recv_from(cx, &mut buf))?;
        decode(&mut buf)?;
        meta[0] = RecvMeta {
            len: buf.filled().len(),
            addr,
            ecn: None,
            dst_ip: None,
        };
        Poll::Ready(Ok(1))
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.io.local_addr()
    }
}

fn encode(buf: &mut Vec<u8>) -> std::io::Result<()> {
    let mut msg = Message::new();
    msg.add_answer({
        let rcd = Record::from_rdata(
            Name::from_utf8("www.apple.com").unwrap(),
            32,
            RData::NULL(NULL::with(buf.to_vec())),
        );
        rcd
    });
    *buf = msg.to_bytes().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "failed to convert the QUIC packet into a DNS message",
        )
    })?;
    Ok(())
}

fn decode(buf: &mut ReadBuf) -> std::io::Result<()> {
    if let Some(record) = Message::from_vec(buf.filled())
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "failed to parse the raw packet into a DNS message",
            )
        })?
        .answers()
        .iter()
        .next()
    {
        match record.rdata() {
            RData::NULL(some) => {
                return some
                    .anything()
                    .and_then(|x| {
                        buf.clear();
                        buf.put_slice(x);
                        Some(())
                    })
                    .ok_or(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "NULL Record doesn't contain any data",
                    ))
            }
            _ => {
                log::warn!("record Type other than NULL");
            }
        }
    } else {
        log::warn!("no answer in DNS packet");
    }
    // We treat it as empty
    buf.clear();
    Ok(())
}
