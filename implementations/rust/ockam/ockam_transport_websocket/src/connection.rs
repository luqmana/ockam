use std::convert::TryInto;

use ockam_router::message::{MAX_MESSAGE_SIZE, ROUTER_ADDRESS_WEBSOCKET, RouterAddress, RouterMessage};
use ockam_transport::{Connection, TransportError};
use async_trait::async_trait;
use async_tungstenite::{WebSocketStream, tungstenite::Message};
use async_tungstenite::tokio::*;
use futures::prelude::*;
use url::Url;

pub struct WebSocketConnection {
    local_address: Option<Url>,
    remote_address: Option<Url>,
    message_buff: Vec<u8>,
    message_length: usize,
    ws_stream: Option<WebSocketStream<ConnectStream>>,
}

impl WebSocketConnection {
    pub fn new(remote_address: &str) -> Result<Self, TransportError> {
        Ok(WebSocketConnection {
            local_address: None,
            remote_address: Some(remote_address.parse().map_err(|_| TransportError::InvalidPeer)?),
            message_buff: vec![],
            message_length: 0,
            ws_stream: None
        })
    }

    pub fn from_stream(local_address: &str, ws_stream: WebSocketStream<ConnectStream>) -> Result<Self, TransportError> {
        Ok(WebSocketConnection {
            local_address: Some(local_address.parse().map_err(|_| TransportError::InvalidPeer)?),
            remote_address: None,
            message_buff: vec![],
            message_length: 0,
            ws_stream: Some(ws_stream)
        })
    }
}

#[async_trait]
impl Connection for WebSocketConnection {
    async fn connect(&mut self) -> Result<(), TransportError> {
        self.ws_stream = Some(connect_async(self.remote_address.as_ref().ok_or(TransportError::InvalidPeer)?)
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

    async fn send_message(&mut self, mut msg: RouterMessage) -> Result<usize, TransportError> {
        let remote_addr = self.get_remote_address();
        if msg.onward_route.addrs[0] != remote_addr {
            msg.onward_route.addrs.insert(0, remote_addr);
        }
        match serde_bare::to_vec::<RouterMessage>(&msg) {
            Ok(mut msg_vec) => {
                if msg_vec.len() > MAX_MESSAGE_SIZE - 2 {
                    return Err(TransportError::IllFormedMessage);
                }

                let len = msg_vec.len() as u16;
                let mut msg_len_vec = len.to_be_bytes().to_vec();
                msg_len_vec.append(&mut msg_vec);

                self.send(&msg_len_vec).await
            }
            Err(_) => Err(TransportError::IllFormedMessage),
        }
    }

    async fn receive_message(&mut self) -> Result<RouterMessage, TransportError> {
        loop {
            let mut recv_buff = [0u8; MAX_MESSAGE_SIZE];

            // first see if we have a complete message from the last call
            // if not, read additional bytes
            if self.message_buff.len() <= self.message_length as usize {
                let bytes_received = self.receive(&mut recv_buff).await?;
                self.message_buff
                    .append(&mut recv_buff[0..bytes_received].to_vec());
            }

            if self.message_length == 0 {
                self.message_length =
                    serde_bare::from_slice::<u16>(&recv_buff[0..])
                    .map_err(|_| TransportError::IllFormedMessage)? as usize;
                let (len, _) = recv_buff.split_at(2);
                self.message_length = u16::from_be_bytes(len.try_into().map_err(|_| TransportError::IllFormedMessage)?) as usize;
                self.message_buff.remove(0);
                self.message_buff.remove(0);
            }

            if self.message_length as usize <= self.message_buff.len() {
                // we have a complete message
                return match serde_bare::from_slice::<RouterMessage>(&self.message_buff) {
                    Ok(mut m) => {
                        // scoot any remaining bytes to the beginning of the buffer
                        for i in 0..self.message_buff.len() - self.message_length {
                            self.message_buff[i] = self.message_buff[i + self.message_length];
                        }
                        self.message_buff
                            .truncate(self.message_buff.len() - self.message_length);
                        self.message_length = 0;

                        // first address in onward route should be ours, remove it
                        m.onward_route.addrs.remove(0);

                        if !m.onward_route.addrs.is_empty()
                            && m.onward_route.addrs[0].address_type == ROUTER_ADDRESS_WEBSOCKET
                        {
                            if self.local_address.is_some() {
                                m.return_route.addrs.push(self.get_local_address());
                            }
                            self.send_message(m).await?;
                            continue;
                        }
                        Ok(m)
                    }
                    Err(_) => Err(TransportError::IllFormedMessage),
                };
            }
        }
    }

    fn get_local_address(&self) -> RouterAddress {
        let ra = serde_bare::to_vec::<_>(self.local_address.as_ref().unwrap().as_str()).unwrap();
        RouterAddress {
            address_type: ROUTER_ADDRESS_WEBSOCKET,
            address: ra,
        }
    }

    fn get_remote_address(&self) -> RouterAddress {
        let ra = serde_bare::to_vec::<_>(self.remote_address.as_ref().unwrap().as_str()).unwrap();
        RouterAddress {
            address_type: ROUTER_ADDRESS_WEBSOCKET,
            address: ra,
        }
    }
}


#[cfg(test)]
mod test {
    use crate::connection::WebSocketConnection;
    use crate::listener::WebSocketListener;
    use ockam_router::message::{ROUTER_ADDRESS_LOCAL, ROUTER_ADDRESS_WEBSOCKET, Route, RouterAddress, RouterMessage};
    use ockam_transport::{Connection, Listener};
    use tokio::{runtime::Builder, task};

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

    async fn ok_listener(a: String) {
        let r = WebSocketListener::bind(&a).await;
        assert!(r.is_ok());

        let mut listener = r.unwrap();
        let connection = listener.accept().await;
        assert!(connection.is_ok());
        let mut connection = connection.unwrap();

        let router_listener_addr = connection.get_local_address();
        let router_local_addr = RouterAddress {
            address_type: ROUTER_ADDRESS_LOCAL,
            address: b"0123".to_vec(),
        };

        match connection.receive_message().await {
            Ok(m) => {
                assert_eq!(
                    m,
                    RouterMessage {
                        version: 1,
                        onward_route: Route {
                            addrs: vec![router_local_addr.clone()],
                        },
                        return_route: Route {
                            addrs: vec![router_listener_addr, router_local_addr],
                        },
                        payload: vec![0u8],
                    }
                );
            }
            Err(e) => {
                panic!("{:?}", e);
            }
        }
    }

    async fn ok_sender(address: String) {
        let address = format!("ws://{}/", address);
        let mut connection =
            WebSocketConnection::new(&address).unwrap();
        let res = connection.connect().await;
        assert!(!res.is_err());

        let listener_addr_as_vec = serde_bare::to_vec::<_>(address.as_str()).unwrap();
        let router_listener_addr = RouterAddress {
            address_type: ROUTER_ADDRESS_WEBSOCKET,
            address: listener_addr_as_vec,
        };
        let router_local_addr = RouterAddress {
            address_type: ROUTER_ADDRESS_LOCAL,
            address: b"0123".to_vec(),
        };

        let m = RouterMessage {
            version: 1,
            onward_route: Route {
                addrs: vec![router_listener_addr.clone(), router_local_addr.clone()],
            },
            return_route: Route {
                addrs: vec![router_listener_addr, router_local_addr],
            },
            payload: vec![0],
        };
        match connection.send_message(m).await {
            Ok(_) => {}
            Err(e) => {
                panic!("{:?}", e);
            }
        }
    }

    async fn run_ok_test(address: String) {
        let a1 = address.clone();
        let j1 = task::spawn(async {
            let f = ok_listener(a1);
            f.await;
        });

        let a2 = address.clone();
        let j2 = task::spawn(async {
            let f = ok_sender(a2);
            f.await;
        });
        let (r1, r2) = tokio::join!(j1, j2);
        if r1.is_err() {
            panic!("{:?}", r1);
        }
        if r2.is_err() {
            panic!("{:?}", r2);
        }
    }

    #[test]
    fn ok_message() {
        let runtime = Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()
            .unwrap();

        runtime.block_on(async {
            println!("run_ok_test starting...");
            run_ok_test("127.0.0.1:4050".to_string()).await;
            println!("run_ok_test done.");
        });
    }
}
