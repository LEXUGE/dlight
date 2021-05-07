use std::{
    convert::TryInto,
    net::{IpAddr, SocketAddr},
};

use bytes::{BufMut, BytesMut};
use num_enum::{FromPrimitive, IntoPrimitive, TryFromPrimitive};
use std::net::ToSocketAddrs;
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    net::TcpStream,
};

// Version of SOCKS proxy protocol
pub const SOCKS_VERSION: u8 = 0x05;

// The reserved bit defined per RFC
pub const RESERVED: u8 = 0x00;

// SOCK5 CMD Type
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum Command {
    Connect = 0x01,
    // Currently unsupported
    Bind = 0x02,
    // Currently unsupported
    UdpAssosiate = 0x3,
}

// Client Authentication Methods
#[derive(Debug, Eq, PartialEq, FromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum AuthMethods {
    // No Authentication
    NoAuth = 0x00,
    // UNSUPPORTED
    GssApi = 0x01,
    // Authenticate with a username / password
    UserPass = 0x02,
    // Methods other than these
    #[num_enum(default)]
    Others,
    // Cannot authenticate
    NoMethods = 0xFF,
}

// Data structure for the client's init message
pub struct InitReq {
    pub version: u8,
    // Methods
    pub mtds: Vec<AuthMethods>,
}

impl InitReq {
    pub async fn read<T>(reader: &mut T) -> anyhow::Result<Self>
    where
        T: AsyncRead + Unpin,
    {
        let version = reader.read_u8().await?;
        let mtd_count = reader.read_u8().await?;
        let mut mtds = vec![0; mtd_count as usize];
        reader.read_exact(&mut mtds).await?;
        let mtds = mtds
            .into_iter()
            .map(|x| x.into())
            .collect::<Vec<AuthMethods>>();
        Ok(Self { version, mtds })
    }
}

// Data structure for the client's init message
pub struct InitReply {
    pub version: u8,
    // Methods
    pub mtd: AuthMethods,
}

impl InitReply {
    pub fn no_method() -> Self {
        Self {
            version: SOCKS_VERSION,
            mtd: AuthMethods::NoMethods,
        }
    }

    pub fn method(mtd: AuthMethods) -> Self {
        Self {
            version: SOCKS_VERSION,
            mtd: mtd,
        }
    }
}

impl From<InitReply> for BytesMut {
    fn from(reply: InitReply) -> Self {
        let mut buf = BytesMut::new();
        buf.put_u8(reply.version);
        buf.put_u8(reply.mtd.into());
        buf
    }
}

// The response code used by cmd reply
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum RespCode {
    Success = 0x00,
    // general SOCKS server failure
    GeneralFailure = 0x01,
    // connection not allowed by ruleset
    RuleFailure = 0x02,
    NetworkUnreachable = 0x03,
    HostUnreachable = 0x04,
    ConnectionRefused = 0x05,
    TtlExpired = 0x06,
    CommandNotSupported = 0x07,
    AddrTypeNotSupported = 0x08,
}

// addr variant types
#[derive(Debug, Eq, PartialEq, TryFromPrimitive, IntoPrimitive)]
#[repr(u8)]
pub enum AddrType {
    V4 = 0x01,
    Domain = 0x03,
    V6 = 0x04,
}

impl From<IpAddr> for AddrType {
    fn from(ip: IpAddr) -> Self {
        match ip {
            IpAddr::V4(_) => Self::V4,
            IpAddr::V6(_) => Self::V6,
        }
    }
}

// The aggregated type for address (e.g. IPv4 and IPv6 addresses).
#[derive(Debug, Eq, PartialEq)]
pub struct Addr {
    // Address Type
    pub atyp: AddrType,
    pub addr: SocketAddr,
}

impl Addr {
    pub async fn read<T>(reader: &mut T) -> anyhow::Result<Self>
    where
        T: AsyncRead + Unpin,
    {
        let atyp: AddrType = reader.read_u8().await?.try_into()?;
        let addr: SocketAddr = match atyp {
            AddrType::V4 => {
                let mut ipaddr = [0u8; 4];
                reader.read_exact(&mut ipaddr).await?;
                let ipaddr: IpAddr = ipaddr.into();
                (ipaddr, reader.read_u16().await?).into()
            }
            // TODO: Can we do it better here?
            AddrType::Domain => {
                let len = reader.read_u8().await?;
                let mut domain = vec![0u8; len as usize];
                reader.read_exact(&mut domain).await?;
                let mut domain = String::from_utf8_lossy(&domain[..]).to_string();
                domain.push_str(&":");
                domain.push_str(&reader.read_u16().await?.to_string());
                domain.to_socket_addrs()?.collect::<Vec<SocketAddr>>()[0]
            }
            AddrType::V6 => {
                let mut ipaddr = [0u8; 16];
                reader.read_exact(&mut ipaddr).await?;
                let ipaddr: IpAddr = ipaddr.into();
                (ipaddr, reader.read_u16().await?).into()
            }
        };
        Ok(Self { atyp, addr })
    }
}

impl From<SocketAddr> for Addr {
    fn from(socket: SocketAddr) -> Self {
        Self {
            atyp: socket.ip().into(),
            addr: socket,
        }
    }
}

impl From<Addr> for BytesMut {
    fn from(addr: Addr) -> BytesMut {
        let mut buf = BytesMut::new();
        buf.put_u8(addr.atyp.into());
        match addr.addr.ip() {
            IpAddr::V4(ip) => buf.put_slice(&mut ip.octets()),
            IpAddr::V6(ip) => buf.put_slice(&mut ip.octets()),
        };
        buf.put_u16(addr.addr.port());
        buf
    }
}

// Command request, last step before transmiting data!
#[derive(Debug, Eq, PartialEq)]
pub struct CmdRequest {
    pub version: u8,
    pub command: Command,
    pub addr: Addr,
}

impl CmdRequest {
    pub async fn read<T>(reader: &mut T) -> anyhow::Result<Self>
    where
        T: AsyncRead + Unpin,
    {
        let version = reader.read_u8().await?;
        let command = reader.read_u8().await?.try_into()?;
        // read the reserved bit
        reader.read_u8().await?;
        let addr = Addr::read(reader).await?;
        Ok(Self {
            version,
            command,
            addr,
        })
    }
}

impl From<CmdRequest> for BytesMut {
    fn from(req: CmdRequest) -> Self {
        let mut buf = BytesMut::new();
        let addr: BytesMut = req.addr.into();
        buf.put_u8(req.version);
        buf.put_u8(RESERVED);
        buf.put_u8(req.command.into());
        buf.extend_from_slice(&addr);
        buf
    }
}

// Reply for the Cmd request
#[derive(Debug, Eq, PartialEq)]
pub struct CmdReply {
    pub version: u8,
    pub code: RespCode,
    pub addr: Addr,
}

impl CmdReply {
    pub fn failure(code: RespCode) -> Self {
        Self {
            version: SOCKS_VERSION,
            code,
            addr: Addr {
                atyp: AddrType::V4,
                addr: "127.0.0.1:1080".parse().unwrap(),
            },
        }
    }

    pub fn success(addr: Addr) -> Self {
        Self {
            version: SOCKS_VERSION,
            code: RespCode::Success,
            addr,
        }
    }

    pub async fn read(reader: &mut TcpStream) -> anyhow::Result<Self> {
        Ok(Self {
            version: reader.read_u8().await?,
            code: reader.read_u8().await?.try_into()?,
            addr: Addr::read(reader).await?,
        })
    }
}

impl From<CmdReply> for BytesMut {
    fn from(req: CmdReply) -> Self {
        let mut buf = BytesMut::new();
        let addr: BytesMut = req.addr.into();
        buf.put_u8(req.version);
        buf.put_u8(req.code.into());
        buf.put_u8(RESERVED);
        buf.extend_from_slice(&addr);
        buf
    }
}

#[cfg(test)]
mod tests {
    use super::{Addr, AddrType};
    use bytes::BytesMut;

    #[test]
    fn addr_parse() {
        let buf: BytesMut = Addr {
            atyp: AddrType::V4,
            addr: ([203, 107, 42, 43], 443).into(),
        }
        .into();
        let buf: Vec<u8> = buf.to_vec();
        assert_eq!(vec![1, 203, 107, 42, 43, 1, 187], buf)
    }
}
