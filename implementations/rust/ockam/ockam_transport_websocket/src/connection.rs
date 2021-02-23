use ockam_router::message::{RouterAddress, RouterMessage};
use ockam_transport::{Connection, TransportError};
use async_trait::async_trait;
use async_tungstenite::{WebSocketStream, tungstenite::Message};
use async_tungstenite::tokio::*;
use futures::prelude::*;
use url::Url;

pub struct WebSocketConnection {
    remote_address: Option<Url>,
    ws_stream: Option<WebSocketStream<ConnectStream>>,
}

impl WebSocketConnection {
    pub fn new(remote_address: &str) -> Result<Self, TransportError> {
        Ok(WebSocketConnection {
            remote_address: Some(remote_address.parse().map_err(|_| TransportError::InvalidPeer)?),
            ws_stream: None
        })
    }

    pub fn from_stream(ws_stream: WebSocketStream<ConnectStream>) -> Result<Self, TransportError> {
        Ok(WebSocketConnection {
            remote_address: None,
            ws_stream: Some(ws_stream)
        })
    }
}

#[async_trait]
impl Connection for WebSocketConnection {
    async fn connect(&mut self) -> Result<(), TransportError> {
        self.ws_stream = Some(connect_async(self.remote_address.as_ref().ok_or(TransportError::InvalidPeer)?.as_str())
            .await
            .map_err(|_| TransportError::ConnectFailed)?
            .0);
        Ok(())
    }

    async fn send(&mut self, buf: &[u8]) -> Result<usize, TransportError> {
        // Note: inefficient
        if let Some(ref mut stream) = self.ws_stream {
            stream.send(Message::binary(buf)).await.map_err(|_| TransportError::CheckConnection)?;
            Ok(buf.len())
        } else {
            Err(TransportError::NotConnected)
        }
    }

    async fn receive(&mut self, buf: &mut [u8]) -> Result<usize, TransportError> {
        if let Some(ref mut stream) = self.ws_stream {
            if let Some(read) = stream.next().await {
                let msg = read.map_err(|_| TransportError::ReceiveFailed)?;
                if !msg.is_binary() {
                    return Err(TransportError::IllFormedMessage);
                }

                let msg_len = msg.len();
                if msg_len >= buf.len() {
                    return Err(TransportError::BufferTooSmall);
                }
                buf[..msg_len].copy_from_slice(&msg.into_data());

                Ok(msg_len)
            } else {
                Err(TransportError::ConnectionClosed)
            }
        } else {
            Err(TransportError::NotConnected)
        }
    }

    async fn send_message(&mut self, _msg: RouterMessage) -> Result<usize, TransportError> {
        todo!()
    }

    async fn receive_message(&mut self) -> Result<RouterMessage, TransportError> {
        todo!()
    }

    fn get_local_address(&self) -> RouterAddress {
        todo!()
    }

    fn get_remote_address(&self) -> RouterAddress {
        todo!()
    }
}


#[cfg(test)]
mod test {
    use crate::connection::WebSocketConnection;
    use ockam_transport::Connection;
    use tokio::runtime::Builder;

    async fn echo_test() {
        let mut connection = WebSocketConnection::new("ws://echo.websocket.org").unwrap();
        connection.connect().await.unwrap();

        let message = b"Hello World!";
        connection.send(message).await.expect("failed to send");

        let mut buf = vec![0; message.len() * 2];
        let recv_len = connection.receive(&mut buf).await.expect("failed to receive");
        assert_eq!(recv_len, message.len());
        assert_eq!(&buf[..recv_len], message);
    }

    #[test]
    pub fn echo_test_single_thread() {
        let runtime = Builder::new_current_thread().enable_io().build().unwrap();

        runtime.block_on(async {
            echo_test().await;
        });
    }
}
