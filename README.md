# u2h

A simple UDP to HTTP translation proxy.

Why? I had a use case in mind and thought of it as an opportunity to see what
it is like to write a network service in Rust, so here it is. This can be used
for whatever purpose, so be creative! It is also meant to be low-configuration,
so you can just dump the binary on a fresh machine and have it running in
minutes.

The proxy operates in either of two modes from the point of view of HTTP:
*client* or *server*.

In client mode, all packets received on a UDP socket are sent to an allocated
HTTP2 stream per source address, incoming packets from that stream are sent
back to the address associated with that stream. In server mode, data from
each HTTP2 stream is copied bi-directionally to a corresponding UDP socket.
Packets are transmitted without any modifications.

TLS certificates are generated in server mode and stored on the file system.
The configured SNI is what sets the SAN. For the client to work, the checksum
of the certificate returned by the server should be passed to the client config,
the same checksum can be taken by running `sha384sum` on the relevant `.cer`
file. SNI on the client side is set via pseudo-DNS resolution, meaning TLS
connections don't understand DNS - who needs DNS anyway?

Since this a single-purpose server-client configuration pair, `User-Agent`
header is checked strictly and the configuration must match on both ends.
It acts as a form of basic authentication.

There's no logging, only in cases of some errors, and these may be quite
cryptic. No telemetry, which would be nice to have. May be later if that proxy
proves to be useful. And no tests, because it was hacked quickly in a day.

Unless there are vulnerabilities in the underlying libraries, it *should*
be safe to have the HTTP server end exposed to the Internet. UDP end in a
client mode should also be OK to expose, although largely depends on the
service being translated, i.e. the receiving UDP side on the other end.

Implementation-wise, it's a single-threaded model for the UDP receive side in
client mode, the rest is handled by the tokio runtime. The HTTP2 stream is
established synchronously upon receiving a UDP packet from a new address.
The only real state, apart from the certificates stored on the filesystem, is
the source address to a stream map in client mode, which is a regular Rust hash
map, but limited to 4k entries and is cleaned up if getting full - if at about
75% capacity, creating a new stream will incur a delay of scanning through the
map.

Run the binary with `help` argument to see how to configure the thing.

## License

Licensed under the MIT license. See [LICENSE](LICENSE).

## Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, shall be licensed as above, without any
additional terms or conditions.
