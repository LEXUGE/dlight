use std::convert::{TryFrom, TryInto};

// `Socket` trait implementations for quinn
use quinn::transport::{Socket, UdpSocket};
use trust_dns_proto::{
    op::message::Message,
    rr::{rdata::null::NULL, record_data::RData, resource::Record, Name},
    serialize::binary::BinEncodable,
};

pub struct DnsSocket {
    udp: UdpSocket,
}

impl TryFrom<std::net::UdpSocket> for DnsSocket {
    type Error = std::io::Error;

    fn try_from(socket: std::net::UdpSocket) -> Result<Self, Self::Error> {
        Ok(Self {
            udp: socket.try_into()?,
        })
    }
}

impl Socket for DnsSocket {
    fn poll_send(
        &self,
        cx: &mut std::task::Context,
        transmits: &mut [quinn::Transmit],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let mut encoded_trans: Vec<quinn::Transmit> = Vec::new();
        for t in transmits {
            let mut transmit = t.clone();
            transmit.contents = encode(&t.contents)?;
            encoded_trans.push(transmit);
        }
        // log::warn!("{:?}", encoded_trans);
        self.udp.poll_send(cx, encoded_trans.as_mut_slice())
    }

    fn poll_recv(
        &self,
        cx: &mut std::task::Context,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn::transport::RecvMeta],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let len = futures::ready!(self.udp.poll_recv(cx, bufs, meta))?;
        // in [0, len)
        for i in 0..len {
            let buf_len = meta[i].len;
            let decoded = decode(&bufs[i][..buf_len])?;
            meta[i].len = decoded.len();
            bufs[i]
                .split_at_mut(decoded.len())
                .0
                .copy_from_slice(decoded.as_slice());
        }
        std::task::Poll::Ready(Ok(len))
    }

    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.udp.local_addr()
    }
}

fn encode(buf: &[u8]) -> std::io::Result<Vec<u8>> {
    let mut msg = Message::new();
    msg.add_answer({
        let rcd = Record::from_rdata(
            Name::from_utf8("www.apple.com").unwrap(),
            32,
            RData::NULL(NULL::with(buf.to_vec())),
        );
        rcd
    });
    msg.to_bytes().map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "failed to convert the QUIC packet into a DNS message",
        )
    })
}

fn decode(buf: &[u8]) -> std::io::Result<Vec<u8>> {
    if let Some(record) = Message::from_vec(&buf)
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
                    .and_then(|x| Some(x.to_vec()))
                    .ok_or(std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "NULL Record doesn't contain any data",
                    ))
            }
            _ => {
                log::warn!("record Type other than NULL")
            }
        }
    } else {
        log::warn!("no answer in DNS packet")
    }
    // We treat the empty packet as normal?
    Ok(Vec::new())
}
