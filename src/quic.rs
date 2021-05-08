use quinn::{
    crypto::rustls::TlsSession,
    generic::{RecvStream, SendStream},
    transport::Socket,
};
use tokio::io::{AsyncRead, AsyncWrite};

pub struct QuinnStream<T: Socket> {
    recv: RecvStream<TlsSession, T>,
    send: SendStream<TlsSession, T>,
}

impl<T: Socket> QuinnStream<T> {
    pub fn new(recv: RecvStream<TlsSession, T>, send: SendStream<TlsSession, T>) -> Self {
        Self { recv, send }
    }
}

impl<T: Socket> AsyncRead for QuinnStream<T> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        AsyncRead::poll_read(std::pin::Pin::new(&mut self.recv), cx, buf)
    }
}

impl<T: Socket> AsyncWrite for QuinnStream<T> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        AsyncWrite::poll_write(std::pin::Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        AsyncWrite::poll_flush(std::pin::Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), std::io::Error>> {
        AsyncWrite::poll_shutdown(std::pin::Pin::new(&mut self.send), cx)
    }

    fn poll_write_vectored(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        let buf = bufs
            .iter()
            .find(|b| !b.is_empty())
            .map_or(&[][..], |b| &**b);
        self.poll_write(cx, buf)
    }

    fn is_write_vectored(&self) -> bool {
        false
    }
}
