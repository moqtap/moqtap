//! WebTransport transport implementation wrapping `wtransport`.

use bytes::Bytes;

use super::{RecvStream, SendStream, TransportError};

/// WebTransport send stream wrapping `wtransport::SendStream`.
pub struct WtSendStream(Option<wtransport::SendStream>);

impl WtSendStream {
    /// Write all bytes to the stream.
    pub async fn write_all(&mut self, buf: &[u8]) -> Result<(), TransportError> {
        self.0.as_mut().ok_or(TransportError::StreamClosed)?.write_all(buf).await.map_err(write_err)
    }

    /// Finish the stream (send FIN).
    ///
    /// Takes ownership of the inner stream and spawns an async task
    /// to complete the finish handshake, since `wtransport` 0.7's
    /// `finish()` is async but our trait is sync.
    pub fn finish(&mut self) -> Result<(), TransportError> {
        if let Some(mut stream) = self.0.take() {
            tokio::spawn(async move {
                let _ = stream.finish().await;
            });
        }
        Ok(())
    }

    /// Reset the stream with `code` as the application error code.
    ///
    /// Returns [`TransportError::StreamClosed`] if the stream was
    /// already finished or reset.
    pub fn reset(&mut self, code: u64) -> Result<(), TransportError> {
        self.0
            .as_mut()
            .ok_or(TransportError::StreamClosed)?
            .reset(varint_code(code)?)
            .map_err(|_| TransportError::StreamClosed)
    }

    /// Borrow the underlying quinn send stream.
    ///
    /// `wtransport`'s own `SendStream::stopped` collapses stopped,
    /// closed and disconnected into a single `StreamWriteError`, which
    /// loses the distinction [`SendStream::stopped`] exists to keep. The
    /// `quinn` feature — enabled for `wtransport` workspace-wide — hands
    /// back the real `quinn::SendStream` instead, so the WebTransport
    /// arm can await exactly the same future the QUIC arm does.
    ///
    /// # Errors
    ///
    /// [`TransportError::StreamClosed`] once [`WtSendStream::finish`]
    /// has moved the inner stream out. The QUIC arm has no such gap:
    /// there the stream survives its own `finish`.
    ///
    /// [`SendStream::stopped`]: super::SendStream::stopped
    pub fn quic_stream(&self) -> Result<&quinn::SendStream, TransportError> {
        Ok(self.0.as_ref().ok_or(TransportError::StreamClosed)?.quic_stream())
    }

    /// Set the stream's send priority.
    ///
    /// Only fails when this wrapper has already released the inner
    /// stream. `wtransport::SendStream::set_priority` returns `()` and
    /// discards quinn's `ClosedStream`, so this arm can never report
    /// that the priority failed to apply — unlike the QUIC arm, which
    /// at least surfaces [`TransportError::StreamClosed`] once quinn has
    /// discarded the stream's send state.
    pub fn set_priority(&self, priority: i32) -> Result<(), TransportError> {
        self.0.as_ref().ok_or(TransportError::StreamClosed)?.set_priority(priority);
        Ok(())
    }
}

/// WebTransport receive stream wrapping `wtransport::RecvStream`.
///
/// The inner stream is held in an `Option` because
/// `wtransport::RecvStream::stop` consumes `self` by value, so
/// [`WtRecvStream::stop`] must be able to move it out from behind a
/// `&mut self`. A `None` inner means the stream was already stopped.
pub struct WtRecvStream(Option<wtransport::RecvStream>);

impl WtRecvStream {
    /// Read data into the buffer. Returns `Ok(Some(n))` with bytes read,
    /// `Ok(None)` on stream end, or `Err` on failure.
    pub async fn read(&mut self, buf: &mut [u8]) -> Result<Option<usize>, TransportError> {
        self.0.as_mut().ok_or(TransportError::StreamClosed)?.read(buf).await.map_err(read_err)
    }

    /// Stop the stream with `code` as the application error code.
    ///
    /// Subsequent calls return [`TransportError::StreamClosed`], since
    /// the inner stream is consumed by the first one.
    pub fn stop(&mut self, code: u64) -> Result<(), TransportError> {
        // Validate the code before taking the stream, so an out-of-range
        // code leaves the stream usable.
        let code = varint_code(code)?;
        self.0.take().ok_or(TransportError::StreamClosed)?.stop(code);
        Ok(())
    }
}

/// Convert an application error code to a `wtransport::VarInt`.
fn varint_code(code: u64) -> Result<wtransport::VarInt, TransportError> {
    wtransport::VarInt::try_from_u64(code)
        .map_err(|_| TransportError::Write(format!("error code {code} exceeds the varint range")))
}

/// Map a `wtransport` read error, keeping the peer's reset code typed.
fn read_err(e: wtransport::error::StreamReadError) -> TransportError {
    match e {
        wtransport::error::StreamReadError::Reset(code) => {
            TransportError::StreamReset(code.into_inner())
        }
        other => TransportError::Read(other.to_string()),
    }
}

/// Map a `wtransport` write error, keeping the peer's stop code typed.
fn write_err(e: wtransport::error::StreamWriteError) -> TransportError {
    match e {
        wtransport::error::StreamWriteError::Stopped(code) => {
            TransportError::Stopped(code.into_inner())
        }
        other => TransportError::Write(other.to_string()),
    }
}

/// Take a WebTransport handshake failure apart into codes plus prose.
///
/// The counterpart to [`quic::handshake_failure`](super::quic::handshake_failure),
/// and it recovers less, because `wtransport` gets less far. That library
/// converts quinn's error into its own before this crate sees it
/// (`impl From<quinn::ConnectionError> for wtransport::error::ConnectionError`),
/// and of the three arms carrying a number it exposes exactly one:
///
/// - `ApplicationClosed` has `code()` — read here, typed.
/// - `QuicProto` holds `code: Option<VarInt>` **privately, with no accessor**,
///   and prints it. This is the arm a rejected certificate lands in, so it is
///   the one worth having: a live relay refusing on an expired certificate
///   reaches us as `"QUIC protocol error: invalid peer certificate: certificate
///   expired: ... (code: 301)"`, and 301 is `0x12D` is TLS alert 45. Recovering
///   it means reading the digits back out of `Display`.
/// - `ConnectionClosed` wraps quinn's own struct in a private tuple field, and
///   quinn prints the code by *name* (`CRYPTO_ERROR`) rather than as a number.
///   Nothing to recover, so nothing is invented.
///
/// Parsing a `Display` is exactly what this crate is trying to spare its
/// callers, and doing it here rather than in each of them is the point: one
/// place, pinned by a test, against a dependency whose version this crate
/// chooses. If a `wtransport` upgrade changes the format the test fails rather
/// than the field silently going quiet.
fn handshake_failure(e: &wtransport::error::ConnectingError) -> super::HandshakeFailure {
    use wtransport::error::{ConnectingError, ConnectionError};

    let reason = e.to_string();
    match e {
        ConnectingError::ConnectionError(ConnectionError::ApplicationClosed(close)) => {
            super::HandshakeFailure::application(close.code().into_inner(), reason)
        }
        ConnectingError::ConnectionError(inner @ ConnectionError::QuicProto(_)) => {
            // `QuicProto` is where quinn's *transport* errors land, so the code
            // recovered here is transport-space and a TLS alert may be read
            // from it.
            match code_in_display(&inner.to_string()) {
                Some(code) => super::HandshakeFailure::transport(code, reason),
                None => super::HandshakeFailure::bare(reason),
            }
        }
        _ => super::HandshakeFailure::bare(reason),
    }
}

/// The number in `wtransport::error::QuicProtoError`'s `" (code: {code})"`.
fn code_in_display(rendered: &str) -> Option<u64> {
    let rest = rendered.rsplit_once("(code: ")?.1;
    rest.chars().take_while(char::is_ascii_digit).collect::<String>().parse().ok()
}

/// WebTransport transport wrapping a `wtransport::Connection`.
pub struct WebTransportTransport(wtransport::Connection);

impl WebTransportTransport {
    /// Create a new WebTransport transport from an established connection.
    pub fn new(conn: wtransport::Connection) -> Self {
        Self(conn)
    }

    /// Open a bidirectional stream.
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream), TransportError> {
        let opening =
            self.0.open_bi().await.map_err(|e| TransportError::Connection(e.to_string()))?;
        let (send, recv) = opening.await.map_err(|e| TransportError::Connection(e.to_string()))?;
        Ok((
            SendStream::WebTransport(WtSendStream(Some(send))),
            RecvStream::WebTransport(WtRecvStream(Some(recv))),
        ))
    }

    /// Accept an incoming bidirectional stream.
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), TransportError> {
        let (send, recv) =
            self.0.accept_bi().await.map_err(|e| TransportError::Connection(e.to_string()))?;
        Ok((
            SendStream::WebTransport(WtSendStream(Some(send))),
            RecvStream::WebTransport(WtRecvStream(Some(recv))),
        ))
    }

    /// Open a unidirectional send stream.
    pub async fn open_uni(&self) -> Result<SendStream, TransportError> {
        let opening =
            self.0.open_uni().await.map_err(|e| TransportError::Connection(e.to_string()))?;
        let send = opening.await.map_err(|e| TransportError::Connection(e.to_string()))?;
        Ok(SendStream::WebTransport(WtSendStream(Some(send))))
    }

    /// Accept an incoming unidirectional stream.
    pub async fn accept_uni(&self) -> Result<RecvStream, TransportError> {
        let recv =
            self.0.accept_uni().await.map_err(|e| TransportError::Connection(e.to_string()))?;
        Ok(RecvStream::WebTransport(WtRecvStream(Some(recv))))
    }

    /// Send a datagram.
    pub fn send_datagram(&self, data: Bytes) -> Result<(), TransportError> {
        self.0.send_datagram(data).map_err(|e| TransportError::SendDatagram(e.to_string()))
    }

    /// Receive a datagram.
    pub async fn recv_datagram(&self) -> Result<Bytes, TransportError> {
        let datagram = self
            .0
            .receive_datagram()
            .await
            .map_err(|e| TransportError::Connection(e.to_string()))?;
        Ok(datagram.payload())
    }

    /// Close the connection.
    pub fn close(&self, code: u32, reason: &[u8]) {
        self.0.close(wtransport::VarInt::from_u32(code), reason);
    }

    /// Get the remote address of the peer.
    pub fn remote_address(&self) -> std::net::SocketAddr {
        self.0.remote_address()
    }

    /// The certificate chain the peer presented, DER-encoded, leaf first.
    ///
    /// `wtransport` has no certificate accessor of its own — a WebTransport
    /// session is HTTP/3 over QUIC and the certificate belongs to the QUIC
    /// handshake underneath it, which that library models by simply holding
    /// the `quinn::Connection` and exposing it behind its `quinn` feature.
    /// That feature is enabled workspace-wide (it is also what
    /// [`WtSendStream::quic_stream`] rests on), so this arm can answer the
    /// question with the *same* code the QUIC arm uses rather than a second
    /// implementation that could drift from it.
    ///
    /// Both arms therefore agree by construction: the same downcast, the same
    /// empty-on-absent rule, the same refusal to interpret the bytes. That
    /// matters more here than it looks, because the probe consuming this
    /// compares a relay's two transports against each other — a difference
    /// between them has to be a difference in the relay, never in how the two
    /// arms read a certificate.
    ///
    /// See `transport::quic::peer_certificates` — spelled as code rather than
    /// as an intra-doc link because it is `pub(crate)`, and a link to it would
    /// be a private-intra-doc-link warning in a public doc comment.
    pub fn peer_certificates(&self) -> Vec<Vec<u8>> {
        super::quic::peer_certificates(self.0.quic_connection())
    }

    /// The application protocol the server selected, from `WT-Protocol`.
    ///
    /// The answer to the offer `available_protocols` serialized — spelled as
    /// code rather than as an intra-doc link because it is private, and a link
    /// to it would be a warning in a public doc comment — and the WebTransport
    /// counterpart to the ALPN `dial_quic_to` returns: from
    /// draft-15 on this is where MOQT settles its version over this transport,
    /// so an accepted session that cannot be asked this says only that
    /// *something* offered was agreeable.
    ///
    /// `None` where the server named nothing — which is every server on a
    /// session opened with no offer, and a conformant server's answer to an
    /// offer it read but chose not to echo.
    ///
    /// # The value is a Structured Field, and this reads it leniently
    ///
    /// [WebTransport] Section 3.3 defines `WT-Protocol` as an sf-string, so a
    /// conformant server sends `"moqt-19"` with the quotes. Those are stripped
    /// here, along with the two escapes an sf-string permits inside them. A
    /// value arriving *without* quotes is not a valid sf-string, but its intent
    /// is unmistakable and it is taken as-is: reporting "no protocol" for a
    /// server that plainly named one would be the worse of the two answers, and
    /// the raw fields are still on [`wtransport::connection::ConnectResponse`]
    /// for a caller that wants to grade the serialization itself.
    ///
    /// [WebTransport]: https://datatracker.ietf.org/doc/html/draft-ietf-webtrans-http3
    #[cfg(feature = "wt-protocol")]
    pub fn wt_protocol(&self) -> Option<String> {
        Some(unquote_sf_string(self.0.connect_response()?.get("wt-protocol")?))
    }

    /// Every field of the CONNECT response, `:status` included, as received.
    ///
    /// [`WebTransportTransport::wt_protocol`] is the one field this crate reads
    /// for itself; this is the rest, unedited, for a caller grading the response
    /// rather than acting on it. Empty where there was none to read.
    #[cfg(feature = "wt-protocol")]
    pub fn connect_response_headers(&self) -> std::collections::HashMap<String, String> {
        self.0.connect_response().map(|r| r.headers().clone()).unwrap_or_default()
    }
}

/// The contents of an sf-string, or the whole token when it is not one.
///
/// The inverse of the quoting in [`available_protocols`], and deliberately not
/// a parser: RFC 8941 allows exactly two escapes inside a string, `\"` and
/// `\\`, so a backslash before anything else is not an escape and is kept.
#[cfg(feature = "wt-protocol")]
fn unquote_sf_string(raw: &str) -> String {
    let inner = match raw.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
        Some(inner) => inner,
        // Not a string at all — return it whole rather than half of it.
        None => return raw.to_string(),
    };

    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(c) = chars.next() {
        match (c, chars.clone().next()) {
            ('\\', Some(next @ ('"' | '\\'))) => {
                out.push(next);
                chars.next();
            }
            _ => out.push(c),
        }
    }
    out
}

/// A DNS resolver that answers every question with one address.
///
/// The mechanism behind [`dial_webtransport_to`]. `wtransport` resolves the
/// session URL itself and takes the *server name* from that URL's host, so the
/// obvious way to reach a chosen address — putting the IP in the URL — also
/// makes the IP the name the certificate is checked against, which is exactly
/// the defect [`dial_quic`](super::dial_quic) was fixed to stop doing.
///
/// Overriding the resolver instead keeps the hostname in the URL, so
/// `wtransport` takes its domain branch and validates against the hostname,
/// while the address it dials is ours to choose.
#[derive(Debug)]
struct PinnedResolver(std::net::SocketAddr);

impl wtransport::config::DnsResolver for PinnedResolver {
    fn resolve(&self, _host: &str) -> std::pin::Pin<Box<dyn wtransport::config::DnsLookupFuture>> {
        let addr = self.0;
        Box::pin(async move { Ok(Some(addr)) })
    }
}

/// The `WT-Available-Protocols` header field name and value for an offer.
///
/// `None` for an empty offer: a header listing nothing is not the same message
/// as no header, and Structured Fields has no serialization for an empty list.
///
/// The value is a Structured Fields List of Strings — `"moqt-20", "moqt-19"` —
/// which is what [WebTransport] Section 3.3 defines the field as. A protocol
/// identifier is a sequence of bytes there, so one that is not ASCII, or that
/// carries a quote or a backslash, has no sf-string serialization; those are
/// dropped rather than escaped into something a peer would read as a different
/// name. Every MoQT identifier is `moqt-` and two digits, so nothing this crate
/// offers is ever dropped.
///
/// The field name is lower-case because HTTP/3 requires it, and `wtransport`
/// forwards what it is given.
fn available_protocols(protocols: &[Vec<u8>]) -> Option<(&'static str, String)> {
    let listed: Vec<String> = protocols
        .iter()
        .filter_map(|p| std::str::from_utf8(p).ok())
        .filter(|p| !p.is_empty() && p.is_ascii() && !p.contains(['"', '\\']))
        .filter(|p| !p.chars().any(|c| c.is_ascii_control()))
        .map(|p| format!("\"{p}\""))
        .collect();
    (!listed.is_empty()).then(|| ("wt-available-protocols", listed.join(", ")))
}

/// Open a WebTransport session to one already-resolved address.
///
/// The WebTransport counterpart to
/// [`dial_quic_to`](super::quic::dial_quic_to), and it exists for the same
/// reason: a caller measuring *which address* a relay answers on cannot use a
/// dial that resolves for it. Without this, "resolves to both families, answers
/// on only one" is observable over QUIC and invisible over WebTransport.
///
/// `path` is the session path, `/` when the relay names none.
///
/// # Why this does not use `build_with_quic_config`
///
/// [`dial_webtransport`] hands `wtransport` a ready-made quinn config, which
/// avoids that library's own `build()` — a function that *panics* when the
/// crypto provider lacks AES-128-GCM. The builder state accepting a quinn
/// config has no `dns_resolver` hook, so pinning an address requires the
/// `with_custom_tls` path and therefore the panicking `build()`.
///
/// That panic is made unreachable rather than tolerated: the conversion
/// `build()` will perform is performed here first, on an equivalent config, and
/// its failure returned as [`DialError::TlsConfig`](super::DialError::TlsConfig).
/// If it succeeds here it cannot fail there.
pub async fn dial_webtransport_to(
    target: &super::QuicTarget,
    path: &str,
    options: &super::QuicDialOptions,
) -> Result<super::Transport, super::DialError> {
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

    let alpn = vec![wtransport::tls::WEBTRANSPORT_ALPN.to_vec()];
    let tls_config = super::quic::rustls_client_config(options, alpn)?;

    // Pre-flight the exact conversion `build()` would `.expect()` on, so the
    // failure it would panic for becomes an error this returns.
    let _: quinn::crypto::rustls::QuicClientConfig =
        tls_config.clone().try_into().map_err(|e| super::DialError::TlsConfig(format!("{e}")))?;

    // Bind in the target's family, as the QUIC dial does. A socket bound to
    // `0.0.0.0` cannot reach a v6 peer, and pinning an address is pointless if
    // the socket cannot carry it.
    let bind: SocketAddr = match target.addr {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };

    let config = wtransport::ClientConfig::builder()
        .with_bind_address(bind)
        .with_custom_tls(tls_config)
        .dns_resolver(PinnedResolver(target.addr))
        .build();

    // `Endpoint::client` binds the socket, so its failure is this machine's and
    // not the peer's — `super::DialError::LocalSocket` and not a
    // `TransportError`, which would reach `ErrorCause::Transport` and have
    // `is_local` answer false: on a host with no IPv6 stack that files our own
    // missing socket against the relay. Unlike the QUIC arm there is not even a
    // `could not bind` in the message for a reader to find, so the variant is
    // the only thing that says whose failure it is.
    let endpoint = wtransport::Endpoint::client(config)
        .map_err(|e| super::DialError::LocalSocket(e.to_string()))?;

    // The hostname, not the address: this is what becomes the server name and
    // the `:authority` of the CONNECT request. The resolver above is what sends
    // the packets to `target.addr` regardless.
    let host = &target.server_name;
    let authority =
        if host.parse::<Ipv6Addr>().is_ok() { format!("[{host}]") } else { host.clone() };
    let url = format!("https://{authority}:{}{}", target.addr.port(), path);

    let connection = endpoint
        .connect(connect_options(&url, &options.wt_protocols))
        .await
        .map_err(|e| TransportError::Handshake(handshake_failure(&e)))?;

    Ok(super::Transport::WebTransport(WebTransportTransport::new(connection)))
}

/// The CONNECT request for `url`, carrying the protocol offer when there is one.
///
/// Built here rather than at each call site so that both dials send the same
/// request for the same options: an option honoured on one transport and
/// dropped on the other is a difference a measurement publishes as a fact
/// about the relay.
fn connect_options(url: &str, protocols: &[Vec<u8>]) -> wtransport::endpoint::ConnectOptions {
    let builder = wtransport::endpoint::ConnectOptions::builder(url);
    match available_protocols(protocols) {
        Some((name, value)) => builder.add_header(name, value).build(),
        None => builder.build(),
    }
}

/// Open a WebTransport session to `url`.
///
/// The public counterpart to [`dial_quic_to`](super::quic::dial_quic_to), and
/// the reason it exists: every draft module already dials WebTransport, but
/// each does it through a private `connect_webtransport` reached only once a
/// draft has been chosen. A caller trying to *discover* the draft has none
/// yet, so it could reach raw QUIC and nothing else — which left auto-detect
/// dialling QUIC alone and timing out against every WebTransport-only relay.
///
/// No ALPN is returned because there is nothing useful to return: a
/// WebTransport session negotiates `h3`, and `h3` names no draft. Which draft
/// is spoken inside it is settled by CLIENT_SETUP's version list on drafts 07
/// through 14, and by `WT-Available-Protocols` from draft-15 on — see
/// [`wt_protocols`](super::QuicDialOptions::wt_protocols). The server's half of
/// that second one is on the returned transport rather than in this signature:
/// `Transport::wt_protocol`, behind the `wt-protocol` feature and so spelled as
/// code rather than linked. It reads off the live connection like
/// [`peer_certificates`](super::Transport::peer_certificates) and unlike the
/// QUIC dial's ALPN, which is returned because quinn hands it back with the
/// handshake.
///
/// `url` is an `https://host:port/path` — `wtransport` resolves the host
/// itself, so unlike the QUIC path this takes no pre-resolved address and
/// keeps no separate server name.
///
/// A certificate is judged here by exactly what
/// [`dial_quic_to`](super::quic::dial_quic_to) judges it by: both dials get
/// their configuration from the same private constructor in `transport::quic`,
/// so one `QuicDialOptions` means one verdict whichever transport carries it.
/// That means keeping the trust decision out of `wtransport`'s own builder
/// settings — `with_native_certs()` for the OS trust store,
/// `with_no_cert_validation()` for none — which would answer it here, where the
/// answer can differ from the QUIC dial's and let the same relay pass over QUIC
/// and fail here. `build_with_quic_config` is the seam that avoids it: it takes
/// a fully-formed `quinn::ClientConfig` and holds no TLS opinion of its own.
pub async fn dial_webtransport(
    url: &str,
    options: &super::QuicDialOptions,
) -> Result<super::Transport, super::DialError> {
    // `h3` and not `options.alpn`: the ALPN of a WebTransport session is fixed
    // by HTTP/3, and offering the MoQT-over-QUIC names a caller may have put in
    // `options` would get the session refused before it existed. Taking the
    // constant from `wtransport` rather than spelling `b"h3"` keeps it tied to
    // whatever the library's own session layer expects to have negotiated.
    let alpn = vec![wtransport::tls::WEBTRANSPORT_ALPN.to_vec()];
    let config = wtransport::ClientConfig::builder()
        .with_bind_default()
        .build_with_quic_config(super::quic::client_config(options, alpn)?);

    // The socket, as in `dial_webtransport_to` — see the note there for why a
    // bind failure is this machine's rather than the peer's.
    let endpoint = wtransport::Endpoint::client(config)
        .map_err(|e| super::DialError::LocalSocket(e.to_string()))?;

    let connection = endpoint
        .connect(connect_options(url, &options.wt_protocols))
        .await
        .map_err(|e| TransportError::Handshake(handshake_failure(&e)))?;

    Ok(super::Transport::WebTransport(WebTransportTransport::new(connection)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The claim in [`handshake_failure`]'s docs, made falsifiable.
    ///
    /// This goes through `wtransport`'s own public
    /// `From<quinn::ConnectionError>`, so it pins the *upstream* conversion and
    /// rendering rather than only this crate's parser. A `wtransport` upgrade
    /// that stops printing the code, or prints it differently, fails here
    /// instead of quietly turning `tls_alert` into `None` on every
    /// WebTransport attempt in a sweep.
    #[test]
    fn a_tls_alert_survives_wtransports_conversion() {
        let quic =
            quinn::ConnectionError::TransportError(quinn::TransportErrorCode::crypto(45).into());
        let converted = wtransport::error::ConnectionError::from(quic);
        let failure =
            handshake_failure(&wtransport::error::ConnectingError::ConnectionError(converted));

        assert_eq!(
            failure.code,
            Some(0x12d),
            "the code wtransport printed did not come back: {}",
            failure.reason
        );
        assert_eq!(failure.tls_alert, Some(45), "0x12d is certificate_expired");
    }

    /// The one arm `wtransport` exposes properly needs no parsing, and must not
    /// be routed through it — `ApplicationClose` renders its code without the
    /// `(code: N)` marker.
    #[test]
    fn an_application_close_is_read_from_the_type() {
        let quic = quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
            error_code: quinn::VarInt::from_u32(271),
            reason: (&b"No WebTransport protocol offered"[..]).into(),
        });
        let converted = wtransport::error::ConnectionError::from(quic);
        let failure =
            handshake_failure(&wtransport::error::ConnectingError::ConnectionError(converted));

        assert_eq!(failure.code, Some(271));
        assert_eq!(failure.tls_alert, None);
    }

    /// A failure that never reached the peer has nothing numeric to report.
    #[test]
    fn a_dns_failure_reports_no_code() {
        let failure = handshake_failure(&wtransport::error::ConnectingError::DnsNotFound);
        assert_eq!(failure.code, None);
        assert_eq!(failure.tls_alert, None);
    }

    /// What this crate serializes, it must read back. The two halves are the
    /// two ends of one negotiation — the offer in `WT-Available-Protocols` and
    /// the answer in `WT-Protocol` — and a mismatch between them would report
    /// the wrong draft rather than failing.
    #[cfg(feature = "wt-protocol")]
    #[test]
    fn every_identifier_this_crate_offers_survives_a_round_trip() {
        for n in 15..=21u8 {
            let name = format!("moqt-{n}");
            let (_, offered) = available_protocols(&[name.clone().into_bytes()])
                .expect("a single well-formed identifier is offerable");
            assert_eq!(unquote_sf_string(&offered), name);
        }
    }

    #[cfg(feature = "wt-protocol")]
    #[test]
    fn a_value_that_is_not_a_string_is_taken_whole() {
        // Non-conformant — an sf-string needs the quotes — but unmistakable,
        // and half a name would be a finding about the wrong draft.
        assert_eq!(unquote_sf_string("moqt-19"), "moqt-19");
        // One quote is not a pair.
        assert_eq!(unquote_sf_string("\"moqt-19"), "\"moqt-19");
    }

    /// The whole negotiation, over a loopback WebTransport session.
    ///
    /// This is the only test in this crate that stands a server up inside
    /// `src/`, and it is here rather than in `tests/` for a manifest reason:
    /// `wtransport` is an optional *dependency*, so an integration test cannot
    /// name it without adding it to `[dev-dependencies]`, which would build it
    /// on every `cargo test -p moqtap-client` even though the default features
    /// include no WebTransport at all.
    ///
    /// What it pins is a chain nothing else covers end to end:
    ///
    /// - the offer really reaches the server, as a Structured Fields list, in a
    ///   header field named `WT-Available-Protocols`;
    /// - the server's `WT-Protocol` answer survives the CONNECT response, which
    ///   upstream `wtransport` 0.7 parses and drops — see
    ///   `moqtap/vendor/wtransport/PATCH.md`. Re-vendoring that library without
    ///   the patch fails here rather than silently answering `None` on every
    ///   dial;
    /// - and the sf-string comes back unquoted.
    ///
    /// The middle one is why this test exists rather than a live sweep standing
    /// in for it. A patch that keeps the *parsed* response hands back what
    /// `wtransport-proto` rebuilt from `:status` alone — every other field
    /// gone, `WT-Protocol` included — and against live relays that reads
    /// exactly like a fleet in which nobody implements the negotiation. Only a
    /// server this side controls tells the two apart.
    #[cfg(feature = "wt-protocol")]
    #[tokio::test]
    async fn the_protocol_a_server_selects_comes_back_from_the_connect_response() {
        use std::net::{Ipv4Addr, SocketAddr};

        let identity =
            wtransport::Identity::self_signed(["localhost"]).expect("localhost is a valid SAN");
        let server = wtransport::Endpoint::server(
            wtransport::ServerConfig::builder()
                .with_bind_default(0)
                .with_identity(identity)
                .build(),
        )
        .expect("a loopback server binds");
        let port = server.local_addr().expect("a bound endpoint has an address").port();

        // What the server saw in the request, sent back out of the task so the
        // offer can be asserted rather than assumed to have gone out.
        let (offered_tx, offered_rx) = tokio::sync::oneshot::channel();
        let accepting = tokio::spawn(async move {
            let request = server.accept().await.await.expect("the session request arrives");
            let _ = offered_tx.send(request.headers().clone());
            let connection = request
                .accept_with_headers([("wt-protocol", "\"moqt-19\"")])
                .await
                .expect("the session is accepted");
            // Held open until the client has read what it came for.
            tokio::time::sleep(std::time::Duration::from_secs(2)).await;
            drop(connection);
        });

        let target = super::super::QuicTarget {
            addr: SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            server_name: "localhost".to_string(),
        };
        let options = super::super::QuicDialOptions::new(vec![b"h3".to_vec()])
            .insecure(true)
            .offering_wt_protocols(vec![b"moqt-20".to_vec(), b"moqt-19".to_vec()]);

        let transport = dial_webtransport_to(&target, "/", &options)
            .await
            .expect("the loopback session establishes");

        assert_eq!(
            transport.wt_protocol().as_deref(),
            Some("moqt-19"),
            "the server named moqt-19 in WT-Protocol and the client must read it back"
        );

        let offered = offered_rx.await.expect("the server reported what it was offered");
        assert_eq!(
            offered.get("wt-available-protocols").map(String::as_str),
            Some("\"moqt-20\", \"moqt-19\""),
            "the offer must reach the server as a Structured Fields list of strings"
        );

        transport.close(0, b"done");
        accepting.abort();
    }

    /// The two escapes RFC 8941 defines, and the backslash that is neither.
    #[cfg(feature = "wt-protocol")]
    #[test]
    fn only_the_two_escapes_are_escapes() {
        assert_eq!(unquote_sf_string(r#""a\"b""#), r#"a"b"#);
        assert_eq!(unquote_sf_string(r#""a\\b""#), r"a\b");
        // `\n` is not an escape sequence in an sf-string, so both characters
        // stay. Inventing a newline here would be reading a different value
        // from the one the server sent.
        assert_eq!(unquote_sf_string(r#""a\nb""#), r"a\nb");
    }
}
