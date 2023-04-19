This is an implementation of a MASQUE proxy (server), and a HTTP 1.1 - MASQUE client proxy (client)
The MASQUE proxy (server) only accepts connect-udp HTTP/3 CONNECT requests as per RFC 9297 / RFC 9298
The HTTP 1.1 <-> MASQUE client accepts HTTP 1.1 CONNECT requests and translate that to HTTP/3 connect-udp REQUESTS to the MASQUE PROXY, and any subsequent tunneled TCP packet is translate to a QUIC DATAGRAM as per RFC 9298.

It is based on masquerade implementation, fixing some things and removing socks interface in the client.

## Examples

MASQUE proxy (server), listening on port 4433 of 127.0.0.1 address for new QUIC connections:

```
cargo run --bin server -- 127.0.0.1:4433
```

HTTP 1.1 / MASQUE client proxy (client), opening a QUIC connection to 127.0.0.1:4433 and listening on 127.0.0.1:8989 for HTTP/1.1 CONNECT requests
```
cargo run --bin client -- 127.0.0.1:4433 127.0.0.1:8989
```

HTTP 1.1 client to open a TCP connection to 127.0.0.1:8989 and send CONNECT requests to 127.0.0.1:6969 through the proxy: 
```
socat - PROXY:127.0.0.1:127.0.0.1:6969,proxyport=8989
```

UDP server listening on 127.0.0.1:6969:
```
nc -l -u 127.0.0.1 6969
```




