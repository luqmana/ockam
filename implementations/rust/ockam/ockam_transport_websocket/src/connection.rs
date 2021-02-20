use async_tungstenite::{WebSocketStream, tungstenite::{Message, client}};
use async_tungstenite::tokio::*;
use futures::prelude::*;

pub struct WebSocketConnection {
    ws_stream: WebSocketStream<ConnectStream>,
}

impl WebSocketConnection {
    /// Creates a new [`WebSocketConnection`] object to initiate a WebSocket connection
    /// to the given URL.
    ///
    /// # Examples
    /// ```ignore
    /// use ockam_transport_websocket::connection::WebSocketConnection;
    ///
    /// ```
    pub async fn connect<R>(request: R) -> Result<Self, String>
    where
        R: client::IntoClientRequest + Unpin,
    {
        let (ws_stream, _) = connect_async(request).await.map_err(|e| e.to_string())?;
        Ok(WebSocketConnection { ws_stream })
    }

    pub fn from_stream(ws_stream: WebSocketStream<ConnectStream>) -> Self {
        WebSocketConnection { ws_stream }
    }

    pub async fn send(&mut self, buf: &[u8]) -> Result<usize, String> {
        // Note: inefficient
        self.ws_stream.send(Message::binary(buf)).await.map_err(|e| e.to_string())?;
        Ok(buf.len())
    }

    pub async fn receive(&mut self, buf: &mut [u8]) -> Result<usize, String> {
        if let Some(read) = self.ws_stream.next().await {
            let msg = read.map_err(|e| e.to_string())?;
            if !msg.is_binary() {
                return Err("invalid message type".to_string());
            }

            let msg_len = msg.len();
            if msg_len > buf.len() {
                return Err("buffer too small".to_string());
            }
            buf[..msg_len].copy_from_slice(&msg.into_data());

            return Ok(msg_len);
        }

        // Is reading nothing an error or alright?
        Ok(0)
    }
}

#[cfg(test)]
mod test {
    use crate::connection::WebSocketConnection;
    use tokio::runtime::Builder;

    async fn echo_test() {
        let mut connection = WebSocketConnection::connect("ws://echo.websocket.org").await.unwrap();

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
