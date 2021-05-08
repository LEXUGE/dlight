use bytes::Buf;
use quinn::transport::RecvMeta;
use std::{
    convert::TryFrom,
    io,
    net::SocketAddr,
    task::{Context, Poll},
};

// Record::from_rdata(
//             Name::from_utf8("gov.cn").unwrap(),
//             600,
//             RData::NULL(NULL::with(buf.to_vec())),
//         );
const DNS_HEADER: [u8; 28] = [
    0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x3, 0x67, 0x6f, 0x76, 0x2, 0x63,
    0x6e, 0x0, 0x0, 0xa, 0x0, 0x1, 0x0, 0x0, 0x2, 0x58,
];

// `Socket` trait implementations for quinn
use quinn::transport::Socket;
use tokio::io::ReadBuf;

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
            let encoded = DNS_HEADER
                // The data length
                .chain(&(transmit.contents.len() as u16).to_be_bytes()[..])
                // The actual content
                .chain(transmit.contents.as_slice())
                .into_iter()
                .collect();
            transmit.contents = encoded;
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
        // We try to get rid of the DNS header
        buf.filled_mut().rotate_left(30);
        meta[0] = RecvMeta {
            len: buf.filled().len() - 30,
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
