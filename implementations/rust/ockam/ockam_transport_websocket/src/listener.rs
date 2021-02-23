use crate::connection::WebSocketConnection;
use ockam_transport::{Connection, Listener, TransportError};
use async_trait::async_trait;
use async_tungstenite::tokio::*;
use tokio::net::{TcpListener, ToSocketAddrs};

pub struct WebSocketListener {
    listener: TcpListener,
}

impl WebSocketListener {
    pub async fn bind<A>(addr: A) -> Result<Self, TransportError>
        where A: ToSocketAddrs,
    {
        let listener = TcpListener::bind(addr).await.map_err(|_| TransportError::Bind)?;
        Ok(WebSocketListener { listener })
    }
}

#[async_trait]
impl Listener for WebSocketListener {
    async fn accept(&mut self) -> Result<Box<dyn Connection + Send>, TransportError> {
        let (stream, _addr) = self.listener.accept().await.map_err(|_| TransportError::Accept)?;
        let ws_stream = accept_async(stream).await.map_err(|_| TransportError::Accept)?;
        Ok(Box::new(WebSocketConnection::from_stream(ws_stream).unwrap() /*XXX */))
    }
}

#[cfg(test)]
mod test {
    use crate::connection::WebSocketConnection;
    use crate::listener::WebSocketListener;
    use ockam_transport::{Connection, Listener};
    use tokio::runtime::Builder;
    use tokio::task;

    async fn accept_test() {
        let server_task = task::spawn(async {
            let mut listener = WebSocketListener::bind("localhost:8080").await.unwrap();
            listener.accept().await.unwrap();
        });

        // Spawn a client to connect to it
        let client_task = task::spawn(async {
            let mut client = WebSocketConnection::new("ws://localhost:8080/").unwrap();
            client.connect().await.unwrap();
        });

        let (r1, r2) = tokio::join!(server_task, client_task);
        assert!(r1.is_ok());
        assert!(r2.is_ok());
    }

    async fn echo_test() {
        let server_task = task::spawn(async {
            let mut listener = WebSocketListener::bind("localhost:8081").await.unwrap();
            let mut ws_conn = listener.accept().await.unwrap();
            let mut buf = [0; 256];
            let recv_len = ws_conn.receive(&mut buf).await.unwrap();
            ws_conn.send(&buf[..recv_len]).await.unwrap();
        });

        // Spawn a client to connect to it
        let client_task = task::spawn(async {
            let mut ws_conn = WebSocketConnection::new("ws://localhost:8081/").unwrap();
            ws_conn.connect().await.unwrap();
            let msg = b"Hello World!";
            ws_conn.send(msg).await.unwrap();
            let mut buf = [0; 256];
            let recv_len = ws_conn.receive(&mut buf).await.unwrap();
            assert_eq!(msg, &buf[..recv_len]);
        });

        let (r1, r2) = tokio::join!(server_task, client_task);
        assert!(r1.is_ok());
        assert!(r2.is_ok());
    }

    #[test]
    pub fn accept_test_multi_thread() {
        let runtime = Builder::new_multi_thread().enable_io().build().unwrap();

        runtime.block_on(async {
            accept_test().await;
        });
    }

    #[test]
    pub fn echo_test_multi_thread() {
        let runtime = Builder::new_multi_thread().enable_io().build().unwrap();

        runtime.block_on(async {
            echo_test().await;
        });
    }
}