use std::{collections, env, fmt, io, net, pin, sync, task, time};

use tokio::io::AsyncWriteExt;

const TLS_SNI: ConfVar = ConfVar(
    "U2H_TLS_SNI",
    "example.com",
    "SNI to send or verify when establishing TLS connection for HTTP.",
);
const H2_USER_AGENT: ConfVar = ConfVar(
    "U2H_H2_USER_AGENT",
    "u2h:a9b1cf3f",
    "User-Agent header to send or verify when sending HTTP CONNECT request.",
);

const CERTS_PATH: ConfVar = ConfVar(
    "U2H_CERTS_PATH",
    "./.u2h",
    "directory to store generated certificates.",
);
const TLS_LISTEN: ConfVar = ConfVar(
    "U2H_TLS_LISTEN",
    "127.0.0.1:50443",
    "ip:port pair to listen for TLS connections.",
);
const H2_SERVER_ID: ConfVar = ConfVar(
    "U2H_H2_SERVER_ID",
    "void",
    "value of the Server header on all HTTP responses.",
);
const H2_BAD_REQUEST_BODY: ConfVar = ConfVar(
    "U2H_H2_BAD_REQUEST_BODY",
    "Bad Request",
    "response body for the requests that cannot be served.",
);
const UDP_BIND: ConfVar = ConfVar(
    "U2H_UDP_BIND",
    "127.0.0.1:0",
    "ip:port pair to bind the source of UDP socket to for every H2 stream, where port 0 means ephemeral port.",
);
const UDP_CONNECT: ConfVar = ConfVar(
    "U2H_UDP_CONNECT",
    "127.0.0.1:50101",
    "ip:port pair to send UDP packets to.",
);

const TLS_CONNECT: ConfVar = ConfVar(
    "U2H_TLS_CONNECT",
    "127.0.0.1:50443",
    "ip:port pair to establish TLS connections.",
);
const TLS_CERT_SHA384SUM: ConfVar = ConfVar(
    "U2H_TLS_CERT_SHA384SUM",
    "",
    "a known SHA384 hash of a DER-encoded certificate to verify against when establishing a TLS connection.",
);
const UDP_LISTEN: ConfVar = ConfVar(
    "U2H_UDP_LISTEN",
    "127.0.0.1:51010",
    "ip:port pair to listen for UDP packets.",
);

struct ConfVar(&'static str, &'static str, &'static str);

impl fmt::Display for ConfVar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} [{}]: {}", self.0, self.1, self.2)
    }
}

macro_rules! get_conf {
    ($name:tt) => {
        env::var($name.0).unwrap_or_else(|_| String::from($name.1))
    };
}

static TLS_CIPHER_SUITES: [rustls::SupportedCipherSuite; 2] = [
    rustls::cipher_suite::TLS13_AES_256_GCM_SHA384,
    rustls::cipher_suite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
];
static TLS_KX_GROUPS: [&rustls::SupportedKxGroup; 1] = [&rustls::kx_group::X25519];
static TLS_PROTOCOL_VERSIONS: [&rustls::SupportedProtocolVersion; 2] =
    [&rustls::version::TLS12, &rustls::version::TLS13];

#[tokio::main]
async fn main() -> io::Result<()> {
    let mut args = env::args();
    // Discard arg 0, which is a command line name
    args.next();

    if args.len() != 1 {
        eprintln!("invalid number of arguments: expected 1");
        return Err(io::Error::from(io::ErrorKind::InvalidInput));
    }

    match args.next().unwrap().as_str() {
        "help" => {
            eprintln!(
                "\
            A simple UDP to HTTP translation proxy. It can operate in two modes:\
            \n  client -> UDP server to HTTP client\
            \n  server -> HTTP server to UDP client\
            \n\nUsage: u2h (client|server)\
            \n\nAll configuration is through environment variables. The variables are:\
            \n  For both server and client mode:\
            \n    {TLS_SNI}\
            \n    {H2_USER_AGENT}\
            \n  For server mode:\
            \n    {CERTS_PATH}\
            \n    {TLS_LISTEN}\
            \n    {H2_SERVER_ID}\
            \n    {H2_BAD_REQUEST_BODY}\
            \n    {UDP_BIND}\
            \n    {UDP_CONNECT}\
            \n  For client mode:\
            \n    {TLS_CONNECT}\
            \n    {TLS_CERT_SHA384SUM}\
            \n    {UDP_LISTEN}",
            );
            Ok(())
        }
        "client" => client().await,
        "server" => server().await,
        mode => {
            eprintln!("invalid mode {mode}: can be either client or server");
            eprintln!("type help for more info");
            Err(io::Error::from(io::ErrorKind::InvalidInput))
        }
    }
}

async fn server() -> io::Result<()> {
    let sni = get_conf!(TLS_SNI);
    let (cert, pkey) = get_or_create_certificate(&sni)?;
    let sha384sum = ring::digest::digest(&ring::digest::SHA384, &cert);
    eprintln!("u2h: certificate digest: {sha384sum:?}");

    let mut tls_config = rustls::ServerConfig::builder()
        .with_cipher_suites(&TLS_CIPHER_SUITES)
        .with_kx_groups(&TLS_KX_GROUPS)
        .with_protocol_versions(&TLS_PROTOCOL_VERSIONS)
        .expect("bad tls protocol versions")
        .with_no_client_auth()
        .with_single_cert(vec![rustls::Certificate(cert)], rustls::PrivateKey(pkey))
        .expect("failed to create tls config");
    tls_config.alpn_protocols = vec![Vec::from(&b"h2"[..])];

    let listen = get_conf!(TLS_LISTEN);
    let listener = tokio::net::TcpListener::bind(&listen).await?;
    eprintln!("h2: listening on: {listen}");

    loop {
        let stream = match listener.accept().await {
            Ok((stream, _)) => stream,
            Err(err) => {
                eprintln!("h2: accept failed: {err}");
                continue;
            }
        };
        let sni = sni.clone();
        let tls_config = tls_config.clone();
        tokio::task::spawn(async move {
            if let Err(err) = handle_incoming(stream, &sni, tls_config).await {
                eprintln!("h2: server failed: {err}");
            }
        });
    }
}

async fn client() -> io::Result<()> {
    let sha384sum =
        ring::test::from_hex(&get_conf!(TLS_CERT_SHA384SUM)).expect("conf: bad cert sha384sum");

    let tls_config = rustls::client::ClientConfig::builder()
        .with_cipher_suites(&TLS_CIPHER_SUITES)
        .with_kx_groups(&TLS_KX_GROUPS)
        .with_protocol_versions(&TLS_PROTOCOL_VERSIONS)
        .expect("bad tls protocol versions")
        .with_custom_certificate_verifier(sync::Arc::new(ServerCertVerifier(sha384sum)))
        .with_no_client_auth();

    let connect = get_conf!(TLS_CONNECT);
    let socketaddr = connect
        .parse::<net::SocketAddr>()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let sni = get_conf!(TLS_SNI);

    let client = reqwest::ClientBuilder::new()
        .resolve(&sni, socketaddr)
        .connect_timeout(time::Duration::from_secs(30))
        .https_only(true)
        .use_preconfigured_tls(tls_config)
        .http2_prior_knowledge()
        .http2_keep_alive_interval(time::Duration::from_secs(60))
        .http2_keep_alive_timeout(time::Duration::from_secs(90))
        .http2_keep_alive_while_idle(true)
        .pool_idle_timeout(None)
        .referer(false)
        .no_brotli()
        .no_deflate()
        .user_agent(get_conf!(H2_USER_AGENT))
        .build()
        .expect("failed to create h2 client");

    let url = format!("https://{connect}/");
    let mut url = reqwest::Url::parse(&url).expect("conf: bad connect address");
    url.set_host(Some(&sni)).expect("conf: bad sni");

    let listen = get_conf!(UDP_LISTEN);
    let sock = sync::Arc::new(tokio::net::UdpSocket::bind(&listen).await?);
    eprintln!("udp: listening on {listen}");

    let mut streams = LimitedHashMap::new(
        collections::HashMap::<
            net::SocketAddr,
            (time::Instant, tokio::io::WriteHalf<reqwest::Upgraded>),
        >::with_capacity(1 << 12),
        (1 << 11) + (1 << 10),
        1 << 10,
    );

    let now = sync::Arc::new(seqlock::SeqLock::new(time::Instant::now()));
    let now_cloned = now.clone();
    tokio::task::spawn(async move {
        loop {
            tokio::time::sleep(time::Duration::from_secs(2)).await;
            let mut now = now_cloned.lock_write();
            *now = time::Instant::now();
        }
    });

    let mut buf = vec![0u8; 1 << 14];
    loop {
        let (len, addr) = sock.recv_from(&mut buf).await?;
        let now = now.read();

        if let Some((time, writer)) = streams.get_mut(&addr) {
            if tokio::io::copy_buf(&mut &buf[..len], writer).await.is_ok() {
                *time = now + time::Duration::from_secs(30);
                continue;
            }
        } else {
            streams.cleanup(
                |_, (time, _)| time < &now,
                |_, (_, mut stream)| {
                    // No clue if shutting down a stream could block, so run
                    // that in a separate task to be on a safe side.
                    tokio::task::spawn(async move { stream.shutdown().await });
                },
            );
            if streams.len() == streams.capacity() {
                eprintln!("u2h: refusing to allocate h2 stream");
                continue;
            }
        }

        let upgraded = match client
            .request(reqwest::Method::CONNECT, url.as_str())
            .send()
            .await
        {
            Ok(response) => {
                if !response.status().is_success() {
                    eprintln!("h2: bad response: {response:?}");
                    continue;
                }
                match response.upgrade().await {
                    Ok(upgraded) => upgraded,
                    Err(error) => {
                        eprintln!("h2: upgrade failed: {error}");
                        continue;
                    }
                }
            }
            Err(error) => {
                eprintln!("h2: request failed: {error}");
                continue;
            }
        };

        let (mut downstream, mut upstream) = tokio::io::split(upgraded);
        if tokio::io::copy_buf(&mut &buf[..len], &mut upstream)
            .await
            .is_err()
        {
            continue;
        }
        streams.insert(addr, (now + time::Duration::from_secs(30), upstream));

        let sock = sock.clone();
        tokio::task::spawn(async move {
            let mut udpstream = DatagramStream(&sock, Some(addr));
            if let Err(err) = tokio::io::copy(&mut downstream, &mut udpstream).await {
                eprintln!("h2 <-> udp: io error: {err}");
            }
        });
    }
}

async fn handle_incoming(
    stream: tokio::net::TcpStream,
    sni: &str,
    tls_config: rustls::ServerConfig,
) -> Result<(), hyper::Error> {
    let acceptor =
        tokio_rustls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream);
    tokio::pin!(acceptor);
    let stream = match acceptor.as_mut().await {
        Ok(start) => {
            let client_hello = start.client_hello();
            if let Some(server_name) = client_hello.server_name() {
                if server_name != sni {
                    return Ok(());
                }
            } else {
                return Ok(());
            }
            match start.into_stream(tls_config.into()).await {
                Ok(stream) => stream,
                Err(_) => {
                    return Ok(());
                }
            }
        }
        Err(_) => return Ok(()),
    };

    let server = hyper::Server::builder(TlsConn(Some(stream)))
        .http2_only(true)
        .http2_keep_alive_interval(time::Duration::from_secs(60))
        .http2_keep_alive_timeout(time::Duration::from_secs(30))
        .http2_max_concurrent_streams(1 << 16)
        .http2_enable_connect_protocol()
        .serve(hyper::service::make_service_fn(|_| async {
            Ok::<_, std::convert::Infallible>(hyper::service::service_fn(handle_h2_request))
        }));
    server.await
}

async fn handle_h2_request(
    request: hyper::Request<hyper::Body>,
) -> Result<hyper::Response<hyper::Body>, hyper::Error> {
    let mut response = if request.method() != hyper::Method::CONNECT
        || request.headers()[hyper::header::USER_AGENT] != get_conf!(H2_USER_AGENT)
    {
        let mut response = hyper::Response::new(hyper::Body::from(get_conf!(H2_BAD_REQUEST_BODY)));
        *response.status_mut() = hyper::StatusCode::BAD_REQUEST;
        response
    } else {
        tokio::task::spawn(async {
            match hyper::upgrade::on(request).await {
                Ok(upgraded) => {
                    if let Err(err) = handle_h2_upgrade(upgraded).await {
                        eprintln!("h2 <-> udp: io error: {err}");
                    };
                }
                Err(err) => eprintln!("h2: upgrade error: {err}"),
            }
        });
        hyper::Response::new(hyper::Body::empty())
    };
    response.headers_mut().insert(
        hyper::header::SERVER,
        get_conf!(H2_SERVER_ID)
            .parse()
            .expect("failed to parse server id"),
    );
    Ok(response)
}

async fn handle_h2_upgrade(mut upgraded: hyper::upgrade::Upgraded) -> io::Result<(u64, u64)> {
    let sock = tokio::net::UdpSocket::bind(get_conf!(UDP_BIND)).await?;
    sock.connect(get_conf!(UDP_CONNECT)).await?;
    let mut udpstream = DatagramStream(&sock, None);
    tokio::io::copy_bidirectional(&mut upgraded, &mut udpstream).await
}

fn get_or_create_certificate(server_name: &str) -> io::Result<(Vec<u8>, Vec<u8>)> {
    use std::io::Write;

    let path: std::path::PathBuf = get_conf!(CERTS_PATH).into();
    std::fs::create_dir_all(&path)?;

    let cer_path = path.join(format!("{server_name}.cer"));
    let key_path = path.join(format!("{server_name}.key"));
    {
        let cer = std::fs::read(&cer_path);
        if cer
            .as_ref()
            .is_err_and(|err| err.kind() != io::ErrorKind::NotFound)
        {
            return Err(cer.unwrap_err());
        }
        let key = std::fs::read(&key_path);
        if key
            .as_ref()
            .is_err_and(|err| err.kind() != io::ErrorKind::NotFound)
        {
            return Err(key.unwrap_err());
        }
        match cer {
            Ok(cer) => match key {
                Ok(key) => return Ok((cer, key)),
                Err(err) => return Err(err),
            },
            Err(err) => {
                if key.is_ok() {
                    return Err(err);
                }
            }
        }
    }

    let mut cer_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&cer_path)?;
    let mut key_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&key_path)?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut permissions = key_file.metadata()?.permissions();
        permissions.set_mode(0o600);
        key_file.set_permissions(permissions)?;
    }

    let mut params = rcgen::CertificateParams::new(vec![String::from(server_name)]);
    params.alg = &rcgen::PKCS_ED25519;
    params.distinguished_name.remove(rcgen::DnType::CommonName);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, server_name);

    let cert = rcgen::Certificate::from_params(params)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let cer = cert
        .serialize_der()
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
    let key = cert.serialize_private_key_der();
    cer_file.write_all(&cer)?;
    cer_file.sync_all()?;
    key_file.write_all(&key)?;
    key_file.sync_all()?;
    Ok((cer, key))
}

struct LimitedHashMap<K, V> {
    map: collections::HashMap<K, V>,
    threshold_enter: usize,
    threshold_leave: usize,
    cleanup: bool,
}

impl<K: std::hash::Hash + Eq, V> LimitedHashMap<K, V> {
    fn new(
        map: collections::HashMap<K, V>,
        threshold_enter: usize,
        threshold_leave: usize,
    ) -> Self {
        assert!(threshold_enter < map.capacity());
        assert!(threshold_leave < map.capacity());
        Self {
            map,
            threshold_enter,
            threshold_leave,
            cleanup: false,
        }
    }

    #[inline(always)]
    fn len(&self) -> usize {
        self.map.len()
    }

    #[inline(always)]
    fn capacity(&self) -> usize {
        self.map.capacity()
    }

    #[inline(always)]
    fn get_mut<Q>(&mut self, k: &Q) -> Option<&mut V>
    where
        K: std::borrow::Borrow<Q>,
        Q: std::hash::Hash + Eq,
    {
        self.map.get_mut(k)
    }

    #[inline(always)]
    fn insert(&mut self, k: K, v: V) -> Option<V> {
        assert!(
            self.map.contains_key(&k) || self.map.len() < self.map.capacity(),
            "write to a full map"
        );
        self.map.insert(k, v)
    }
}

impl<K, V> LimitedHashMap<K, V> {
    fn cleanup<F: Fn(&K, &V) -> bool, U: FnMut(&K, V)>(&mut self, pred: F, mut remove: U)
    where
        K: Copy + std::hash::Hash + Eq,
    {
        if !self.cleanup && self.map.len() >= self.threshold_enter {
            eprintln!("u2h: entering clean up mode: length={}", self.map.len());
            self.cleanup = true;
        }
        if self.cleanup {
            let mut pos = 0;
            let mut unused = [None; 32];
            for (key, value) in self.map.iter() {
                if pred(key, value) {
                    unused[pos] = Some(*key);
                    pos += 1;
                }
                if pos == unused.len() {
                    break;
                }
            }
            while pos != 0 {
                pos -= 1;
                let key = &unused[pos].unwrap();
                remove(key, self.map.remove(key).unwrap());
            }
        }
        if self.cleanup && self.map.len() < self.threshold_leave {
            eprintln!("u2h: leaving clean up mode: length={}", self.map.len());
            self.cleanup = false;
        }
    }
}

struct TlsConn(Option<tokio_rustls::server::TlsStream<tokio::net::TcpStream>>);

impl hyper::server::accept::Accept for TlsConn {
    type Conn = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type Error = io::Error;

    fn poll_accept(
        mut self: pin::Pin<&mut Self>,
        _cx: &mut task::Context<'_>,
    ) -> task::Poll<Option<Result<Self::Conn, Self::Error>>> {
        if self.0.is_none() {
            return task::Poll::Ready(None);
        }
        let (_, state) = self.0.as_ref().unwrap().get_ref();
        if state.is_handshaking() {
            return task::Poll::Pending;
        }
        task::Poll::Ready(Some(Ok(self.0.take().unwrap())))
    }
}

struct DatagramStream<'a>(&'a tokio::net::UdpSocket, Option<net::SocketAddr>);

impl<'a> tokio::io::AsyncRead for DatagramStream<'a> {
    fn poll_read(
        self: pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> task::Poll<io::Result<()>> {
        self.0.poll_recv(cx, buf)
    }
}

impl<'a> tokio::io::AsyncWrite for DatagramStream<'a> {
    fn poll_write(
        self: pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
        buf: &[u8],
    ) -> task::Poll<io::Result<usize>> {
        match self.0.poll_send_ready(cx) {
            task::Poll::Ready(result) => result,
            task::Poll::Pending => return task::Poll::Pending,
        }?;
        if self.1.is_some() {
            self.0.poll_send_to(cx, buf, self.1.unwrap())
        } else {
            self.0.poll_send(cx, buf)
        }
    }

    fn poll_flush(
        self: pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<io::Result<()>> {
        self.0.poll_send_ready(cx)
    }

    fn poll_shutdown(
        self: pin::Pin<&mut Self>,
        cx: &mut task::Context<'_>,
    ) -> task::Poll<io::Result<()>> {
        self.0.poll_send_ready(cx)
    }
}

struct ServerCertVerifier(Vec<u8>);

impl rustls::client::ServerCertVerifier for ServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::client::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        let sha384sum = ring::digest::digest(&ring::digest::SHA384, &end_entity.0);
        if sha384sum.as_ref() != self.0 {
            eprintln!("u2h: certificate digest mismatch: got {sha384sum:?}");
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        } else {
            Ok(rustls::client::ServerCertVerified::assertion())
        }
    }
}
