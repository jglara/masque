use std::env;

use quiche;
use quiche::h3::{NameValue, Header};
use ring::rand::*;

use std::future::Future;
use std::net::{ToSocketAddrs, SocketAddr};
use std::collections::HashMap;
use std::error::{Error, self};
use std::time::Duration;

use tokio::io::{AsyncWriteExt, AsyncReadExt};
use tokio::net::{UdpSocket, TcpStream, TcpListener};
use tokio::sync::mpsc::{self, UnboundedSender, UnboundedReceiver};
use tokio::time;
use masque::*;
use log::*;


#[derive(Debug)]
enum Content {
    Request {
        headers: Vec<quiche::h3::Header>,
        response_sender: mpsc::UnboundedSender<Content>,
    },
    Headers {
	stream_id: u64,
        headers: Vec<quiche::h3::Header>,
    },
    Datagram {
        payload: Vec<u8>,
    },
    Finished,
}

#[derive(Debug)]
struct ToSend {
    stream_id: u64, // or flow_id for DATAGRAM
    content: Content,
    finished: bool,
}

#[derive(Debug, Clone)]
struct RunBeforeBindError;

impl std::fmt::Display for RunBeforeBindError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "bind(listen_addr) has to be called before run()")
    }
}
impl Error for RunBeforeBindError {}

struct Client {
    listener: Option<TcpListener>,
}

impl Client {
    pub fn new() -> Client {
        Client { listener: None }
    }

    /**
     * returns None if client is not bound to a socket yet
     */
    pub fn listen_addr(&self) -> Option<SocketAddr> {
        return self.listener.as_ref().map(|listener| listener.local_addr().unwrap())
    }

    /**
     * Bind the server to listen to an address
     */
    pub async fn bind<T: tokio::net::ToSocketAddrs>(&mut self, bind_addr: T) -> Result<(), Box<dyn Error>> {
        debug!("creating TCP listener");

        let mut listener = TcpListener::bind(bind_addr).await?;
        debug!("listening on {}", listener.local_addr().unwrap());
        
        self.listener = Some(listener);
        Ok(())
    }
    
    /**
     * Run client to receive TCP connections at the binded address, and handle 
     * incoming streams with stream_handler (e.g. handshake, negotiation, proxying traffic)
     * 
     * This enables any protocol that accepts TCP connection to start with, such as HTTP1.1
     * CONNECT and SOCKS5 as implemented below. Similarly, UDP listening can be easily 
     * added if necessary.
     */
    pub async fn run<F, Fut>(&mut self, server_addr: &String, mut stream_handler: F) -> Result<(), Box<dyn Error>>                                                                                                
    where
	F: FnMut(TcpStream, UnboundedSender<ToSend>) -> Fut,
	Fut: Future<Output = ()> + Send + 'static,  
    {
        if self.listener.is_none() {
            return Err(Box::new(RunBeforeBindError));
        }
        let listener = self.listener.as_mut().unwrap();

        let server_name = format!("https://{}", server_addr); // TODO: avoid duplicate https://
    
        // Resolve server address.
        let url = url::Url::parse(&server_name).unwrap();
        let peer_addr = url.to_socket_addrs().unwrap().next().unwrap();
        
        debug!("creating socket");
        let socket = UdpSocket::bind("0.0.0.0:0".parse::<SocketAddr>().unwrap()).await?;
        socket.connect(peer_addr.clone()).await?;
//        let socket = Arc::new(socket);
        debug!("connecting to {} at {}", server_name, peer_addr);
        
    
        let mut buf = [0; 65535];
        let mut out = [0; MAX_DATAGRAM_SIZE];
    
        let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

	let mut keylog = None;

	if let Some(keylog_path) = std::env::var_os("SSLKEYLOGFILE") {
            let file = std::fs::OpenOptions::new()
		.create(true)
		.append(true)
		.open(keylog_path)
		.unwrap();
	    
            keylog = Some(file);

            config.log_keys();
	}
	
        // TODO: *CAUTION*: this should not be set to `false` in production!!!
        config.verify_peer(false);
    
        config.set_application_protos(quiche::h3::APPLICATION_PROTOCOL).unwrap();
        
        config.set_max_idle_timeout(1000);
        config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
        config.set_initial_max_data(10_000_000);
        config.set_initial_max_stream_data_bidi_local(1_000_000);
        config.set_initial_max_stream_data_bidi_remote(1_000_000);
        config.set_initial_max_stream_data_uni(1_000_000);
        config.set_initial_max_streams_bidi(100);
        config.set_initial_max_streams_uni(100);
        config.set_disable_active_migration(true);
        config.enable_dgram(true, 1000, 1000);
	

    
        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        let rng = SystemRandom::new();
        rng.fill(&mut scid[..]).unwrap();
        let scid = quiche::ConnectionId::from_ref(&scid);
        
        // Client connection.
        let local_addr = socket.local_addr().unwrap();
        let mut conn = quiche::connect(url.domain(), &scid, local_addr, peer_addr, &mut config).expect("quic connection failed");
        info!(
            "connecting to {:} from {:} with scid {}",
            peer_addr,
            socket.local_addr().unwrap(),
            hex_dump(&scid)
        );

	if let Some(keylog) = &mut keylog {
            if let Ok(keylog) = keylog.try_clone() {
		conn.set_keylog(Box::new(keylog));
            }
	}
    
        let (write, send_info) = conn.send(&mut out).expect("initial send failed"); 
        while let Err(e) = socket.send_to(&out[..write], send_info.to).await {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                debug!("send_to() would block");
                continue;
            }
            panic!("UDP socket send_to() failed: {:?}", e);
        }
        debug!("written {}", write);
    
        let mut http3_conn: Option<quiche::h3::Connection> = None;
        let (http3_sender, mut http3_receiver) = mpsc::unbounded_channel::<ToSend>();
        let mut connect_streams: HashMap<u64, UnboundedSender<Content>> = HashMap::new();
        let mut http3_retry_send: Option<ToSend> = None;
        let mut interval = time::interval(Duration::from_millis(20));
        interval.set_missed_tick_behavior(time::MissedTickBehavior::Delay);
        loop {
            if conn.is_closed() {
                info!("connection closed, {:?}", conn.stats());
                break;
            }
    
            tokio::select! {
                // handle QUIC received data
                recvd = socket.recv_from(&mut buf) => {
                    let (read, from) = match recvd {
                        Ok(v) => v,
                        Err(e) => {
                            error!("error when reading from UDP socket");
                            continue
                        },
                    };
                    debug!("received {} bytes", read);
                    let recv_info = quiche::RecvInfo {
                        to: local_addr,
                        from,
                    };
    
                    // Process potentially coalesced packets.
                    let read = match conn.recv(&mut buf[..read], recv_info) {
                        Ok(v) => v,
    
                        Err(e) => {
                            error!("QUIC recv failed: {:?}", e);
                            continue
                        },
                    };
                    debug!("processed {} bytes", read);
    
                    if let Some(http3_conn) = &mut http3_conn {
                        // Process HTTP/3 events.
                        loop {
                            debug!("polling on http3 connection");
                            match http3_conn.poll(&mut conn) {
                                Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                                    info!("got response headers {:?} on stream id {}", hdrs_to_strings(&list), stream_id);
                                    if let Some(sender) = connect_streams.get(&stream_id) {
                                        sender.send(Content::Headers { stream_id, headers: list });
                                    }
                                },
            
                                Ok((stream_id, quiche::h3::Event::Data)) => {
                                    debug!("received stream data");
                                },
            
                                Ok((stream_id, quiche::h3::Event::Finished)) => {
                                    info!("finished received, stream id: {} closing", stream_id);
                                    if let Some(sender) = connect_streams.get(&stream_id) {
                                        connect_streams.remove(&stream_id);
                                    }
                                },
            
                                Ok((stream_id, quiche::h3::Event::Reset(e))) => {
                                    error!("request was reset by peer with {}, stream id: {} closed", e, stream_id);
                                    if let Some(sender) = connect_streams.get(&stream_id) {
                                        connect_streams.remove(&stream_id);
                                    }
                                },
            
                                Ok((_flow_id, quiche::h3::Event::Datagram)) => {
                                    loop {
                                        match http3_conn.recv_dgram(&mut conn, &mut buf) {
                                            Ok((read, flow_id, flow_id_len)) => {
                                                debug!("got {} bytes of datagram on flow {} ({})", read, flow_id, _flow_id);
                                                //trace!("{}", unsafe {std::str::from_utf8_unchecked(&buf[flow_id_len..read])});
                                                if let Some(sender) = connect_streams.get(&flow_id) {
                                                    sender.send(Content::Datagram { payload: buf[flow_id_len..read].to_vec() });
                                                } else {
                                                    debug!("received datagram on unknown flow: {}", flow_id)
                                                }
                                            },
                                            Err(quiche::h3::Error::Done) => {
                                                debug!("done recv_dgram");
                                                break;
                                            },
                                            Err(e) => {
                                                error!("error recv_dgram(): {}", e);
                                                break;
                                            }
                                        }
                                    }
                                },
            
                                Ok((_, quiche::h3::Event::PriorityUpdate)) => unreachable!(),
            
                                Ok((goaway_id, quiche::h3::Event::GoAway)) => {
                                    info!("GOAWAY id={}", goaway_id);
                                },
            
                                Err(quiche::h3::Error::Done) => {
                                    debug!("poll done");
                                    break;
                                },
            
                                Err(e) => {
                                    error!("HTTP/3 processing failed: {:?}", e);
                                    break;
                                },
                            }
                        }
                    }
                },
                // Send pending HTTP3 data in channel to HTTP3 connection on QUIC
                http3_to_send = http3_receiver.recv(), if http3_conn.is_some() && http3_retry_send.is_none() => {
                    if http3_to_send.is_none() {
                        unreachable!()
                    }
                    let mut to_send = http3_to_send.unwrap();
                    let http3_conn = http3_conn.as_mut().unwrap();
                    loop {
                        let result = match &to_send.content {
                            Content::Headers { .. } => unreachable!(),
                            Content::Request { headers, response_sender } => {
                                debug!("sending http3 request {:?}", hdrs_to_strings(&headers));
                                match http3_conn.send_request(&mut conn, &headers, to_send.finished) {
                                    Ok(stream_id) => {
					connect_streams.insert(stream_id, response_sender.clone());
                                        Ok(())
                                    },
                                    Err(e) => {
                                        error!("http3 request send failed");
                                        Err(e)
                                    },
                                }
                            },

                            Content::Datagram {payload } => {
                                debug!("sending http3 datagram of {} bytes to flow {}", payload.len(), to_send.stream_id);
				// encode context_id 0
				let mut enc_context_id = encode_var_int(0);
				enc_context_id.append(&mut payload.clone());
                                http3_conn.send_dgram(&mut conn, to_send.stream_id, &enc_context_id)
                            },

			    Content::Finished => {
				debug!("shutting down stream");
                                conn.stream_shutdown(to_send.stream_id, quiche::Shutdown::Read, 0);
                                match conn.stream_shutdown(to_send.stream_id, quiche::Shutdown::Write, 0) {
                                    Ok(v) => Ok(v),
                                    Err(e) => {
                                        error!("stream shutdown failed: {}", e);
                                        Ok(()) // ignore the error
                                    } 
                                }
			    }

                        };
                        match result {
                            Ok(_) => {},
                            Err(quiche::h3::Error::StreamBlocked | quiche::h3::Error::Done) => {
                                debug!("Connection {} stream {} stream blocked, retry later", conn.trace_id(), to_send.stream_id);
                                http3_retry_send = Some(to_send);
                                break; 
                            },
                            Err(e) => {
                                error!("Connection {} stream {} send failed {:?}", conn.trace_id(), to_send.stream_id, e);
                                conn.stream_shutdown(to_send.stream_id, quiche::Shutdown::Read, 0);
                                conn.stream_shutdown(to_send.stream_id, quiche::Shutdown::Write, 0);
                                {
                                    connect_streams.remove(&to_send.stream_id);
                                }
                            }
                        };
                        to_send = match http3_receiver.try_recv() {
                            Ok(v) => v,
                            Err(e) => break,
                        };
                    }
                },

		// Accept a new TCP connection                                                                                                                                                                    
                tcp_accepted = listener.accept() => {                                                                                                                                                             
                    match tcp_accepted {
                        Ok((tcp_socket, addr)) => {
                            debug!("accepted connection from {}", addr);
                            tokio::spawn(stream_handler(tcp_socket, http3_sender.clone()));
                        },                                                                     
                        Err(_) => todo!(),
                    };
                },       


                // Retry sending in case of stream blocking
                _ = interval.tick(), if http3_conn.is_some() && http3_retry_send.is_some() => {
                    let mut to_send = http3_retry_send.unwrap();
                    let http3_conn = http3_conn.as_mut().unwrap();
                    let result = match &to_send.content {
                        Content::Headers { .. } => unreachable!(),
                        Content::Request { headers, response_sender } => {
                            debug!("retry sending http3 request {:?}", hdrs_to_strings(&headers));
                            match http3_conn.send_request(&mut conn, headers, to_send.finished) {
                                Ok(stream_id) => {
                                    //stream_id_sender.send(stream_id).await;
                                    Ok(())
                                },
                                Err(e) => {
                                    error!("http3 request send failed");
                                    Err(e)
                                },
                            }
                        },

                        Content::Datagram { payload } => {
                            debug!("retry sending http3 datagram of {} bytes", payload.len());
                            http3_conn.send_dgram(&mut conn, to_send.stream_id, &payload)
                        },

			Content::Finished => {
			    todo!()
			}
                    };
                    match result {
                        Ok(_) => {
                            http3_retry_send = None;
                        },
                        Err(quiche::h3::Error::StreamBlocked | quiche::h3::Error::Done) => {
                            debug!("Connection {} stream {} stream blocked, retry later", conn.trace_id(), to_send.stream_id);
                            http3_retry_send = Some(to_send);
                        },
                        Err(e) => {
                            error!("Connection {} stream {} send failed {:?}", conn.trace_id(), to_send.stream_id, e);
                            conn.stream_shutdown(to_send.stream_id, quiche::Shutdown::Write, 0);
                            {
                                connect_streams.remove(&to_send.stream_id);
                            }
                            http3_retry_send = None;
                        }
                    };
                },
    
                else => break,
            }
            
            // Create a new HTTP/3 connection once the QUIC connection is established.
            if conn.is_established() && http3_conn.is_none() {
                let h3_config = quiche::h3::Config::new().unwrap();
                http3_conn = Some(
                    quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                    .expect("Unable to create HTTP/3 connection, check the server's uni stream limit and window size"),
                );
            }
        // Send pending QUIC packets
            loop {
                let (write, send_info) = match conn.send(&mut out) {
                    Ok(v) => v,
    
                    Err(quiche::Error::Done) => {
                        debug!("QUIC connection {} done writing", conn.trace_id());
                        break;
                    },
    
                    Err(e) => {
                        error!("QUIC connection {} send failed: {:?}", conn.trace_id(), e);
    
                        conn.close(false, 0x1, b"fail").ok();
                        break;
                    },
                };
    
                match socket.send_to(&out[..write], send_info.to).await {
                    Ok(written) => debug!("{} written {} bytes out of {}", conn.trace_id(), written, write),
                    Err(e) => panic!("UDP socket send_to() failed: {:?}", e),
                }
            }
    
        }
    
        Ok(())
    }
}


async fn handle_http1_stream(mut stream: TcpStream, http3_sender: UnboundedSender<ToSend>) {
    let mut buf = [0; 65535];
    let mut pos = match stream.read(&mut buf).await {
        Ok(v) => v,
        Err(e) => {
            error!("Error reading from TCP stream: {}", e);
            return
        },
    };
    loop {
        match stream.try_read(&mut buf[pos..]) {
            Ok(read) => pos += read,
            Err(ref e) if would_block(e) => break,
            Err(ref e) if interrupted(e) => continue,
            Err(e) => {
                error!("Error reading from TCP stream: {}", e);
                return
            }
        };
    }
    let peer_addr = stream.peer_addr().unwrap();

    let mut headers = [httparse::EMPTY_HEADER; 16];
    let mut req = httparse::Request::new(&mut headers);
    let res = req.parse(&buf[..pos]).unwrap();
    if let Some(method) = req.method {
        if let Some(path) = req.path {
            if method.eq_ignore_ascii_case("CONNECT") {
		let host_port = path.split(":").collect::<Vec<_>>();
		assert!(host_port.len() == 2);

                let headers = vec![
                    quiche::h3::Header::new(b":method", b"CONNECT"),
		    quiche::h3::Header::new(b":path", format!("/.well_known/masque/udp/{}/{}/", host_port[0], host_port[1]).as_bytes()),
                    quiche::h3::Header::new(b":protocol", b"connect-udp"),
                    quiche::h3::Header::new(b":scheme", b"dummy-scheme"),
                    quiche::h3::Header::new(b":authority", b"dummy-authority"),
                    quiche::h3::Header::new(b":authorization", b"dummy-authorization"),    
                ];
                info!("sending HTTP3 request {:?}", headers);

                let (response_sender, mut response_receiver) = mpsc::unbounded_channel::<Content>();
                http3_sender.send(ToSend { content: Content::Request { headers, response_sender }, finished: false, stream_id: u64::MAX});

		let mut connect_stream_id = 0;
                let response = response_receiver.recv().await.expect("http3 response receiver error");
                if let Content::Headers { stream_id, headers } = response {
                    info!("Got response {:?} from stream_id: {}", hdrs_to_strings(&headers), stream_id);
		    connect_stream_id = stream_id;
                    let mut status = None;
                    for hdr in headers {
                        match hdr.name() {
                            b":status" => status = Some(hdr.value().to_owned()),
                            _ => (),
                        }
                    }
                    if let Some(status) = status {
                        if let Ok(status_str) = std::str::from_utf8(&status) {
                            if let Ok(status_code) = status_str.parse::<i32>() {
                                if status_code >= 200 && status_code < 300 {
                                    info!("connection established, sending 200 OK");
                                    stream.write(&b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n".to_vec()).await;
                                }
                            }
                        }
                    }
                } else {
                    error!("received others when expecting headers for connect");
                }

                let (mut read_half, mut write_half) = stream.into_split();
                let http3_sender_clone = http3_sender.clone();
                let read_task = tokio::spawn(async move {
                    let mut buf = [0; 65535];
                    loop {
                        let read = match read_half.read(&mut buf).await {
                            Ok(v) => v,
                            Err(e) => {
                                error!("Error reading from TCP {}: {}", peer_addr, e);
                                break
                            },
                        };
                        if read == 0 {
                            debug!("TCP connection closed from {}", peer_addr);
                            http3_sender_clone.send(ToSend { stream_id: connect_stream_id, content: Content::Finished, finished: false });
                            break
                        }
                        debug!("read {} bytes from TCP from {} for stream {}", read, peer_addr, connect_stream_id);
                        http3_sender_clone.send(ToSend { stream_id: connect_stream_id, content: Content::Datagram { payload: buf[..read].to_vec() }, finished: false });
                    }
                });
                let write_task = tokio::spawn(async move {
                    loop {
                        let data = match response_receiver.recv().await {
                            Some(v) => v,
                            None => {
                                debug!("TCP receiver channel closed for stream {}", connect_stream_id);
                                break
                            },
                        };
                        match data {
                            Content::Request { .. } => unreachable!(),
                            Content::Headers { .. } => unreachable!(),
                            Content::Datagram { payload } => {
				// decode context_id
				let (context_id, payload) = decode_var_int(&payload);
				debug!("received UDP Proxying Datagram with context_id={:?} ", context_id);

				let mut pos: usize = 0;
                                while pos < payload.len() {
                                    let bytes_written: usize = match write_half.write(&payload[pos..]).await {
                                        Ok(v) => v,
                                        Err(e) => {
                                            error!("Error writing to TCP {} on stream id {}: {}", peer_addr, connect_stream_id, e);
                                            return
                                        },
                                    };
                                    pos += bytes_written;
                                }
                                debug!("written {} bytes from TCP to {} for stream {}", payload.len(), peer_addr, connect_stream_id);     
			    }
			    Content::Finished => {
				debug!("shutting down stream in write task");
                                break;
			    }
                        };
                        
                    }
                });
                tokio::join!(read_task, write_task);
                
                return
            }
        }
    }
    stream.write(&b"HTTP/1.1 400 Bad Request\r\n\r\n".to_vec()).await;
}

pub struct Http1Client {
    client: Client,
}

impl Http1Client {
    pub fn new() -> Http1Client {
        Http1Client { client: Client::new() }
    }

    pub fn listen_addr(&self) -> Option<SocketAddr> {
        return self.client.listen_addr()
    }

    pub async fn bind<T: tokio::net::ToSocketAddrs>(&mut self, bind_addr: T) -> Result<(), Box<dyn Error>> {
        self.client.bind(bind_addr).await
    }

    pub async fn run(&mut self, server_addr: &String) -> Result<(), Box<dyn Error>> {
        self.client.run(server_addr, handle_http1_stream).await
    }
}



#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    env_logger::builder().format_timestamp_millis().init();

    let server_name = env::args()
        .nth(1)
        .unwrap_or_else(|| "127.0.0.1:4433".to_string());
    
    let bind_addr = env::args()
        .nth(2)
        .unwrap_or_else(|| "127.0.0.1:8899".to_string());

    let mut client: Http1Client = Http1Client::new();                                                                                                                                                      
    client.bind(bind_addr).await?;                                                                                                                                                                         
    client.run(&server_name).await   

}


