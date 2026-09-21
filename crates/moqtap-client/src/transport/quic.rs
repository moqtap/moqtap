//! QUIC transport implementation wrapping quinn.

use std::future::Future;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use bytes::Bytes;

use super::{RecvStream, SendStream, TransportError};

/// QUIC transport wrapping a `quinn::Connection`.
pub struct QuicTransport {
    conn: quinn::Connection,
}

impl QuicTransport {
    /// Create a new QUIC transport from a quinn connection.
    pub fn new(conn: quinn::Connection) -> Self {
        Self { conn }
    }

    /// Open a bidirectional stream.
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream), TransportError> {
        let (send, recv) = self.conn.open_bi().await.map_err(conn_err)?;
        Ok((SendStream::Quic(send), RecvStream::Quic(recv)))
    }

    /// Accept an incoming bidirectional stream.
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), TransportError> {
        let (send, recv) = self.conn.accept_bi().await.map_err(conn_err)?;
        Ok((SendStream::Quic(send), RecvStream::Quic(recv)))
    }

    /// Open a unidirectional send stream.
    pub async fn open_uni(&self) -> Result<SendStream, TransportError> {
        let send = self.conn.open_uni().await.map_err(conn_err)?;
        Ok(SendStream::Quic(send))
    }

    /// Accept an incoming unidirectional stream.
    pub async fn accept_uni(&self) -> Result<RecvStream, TransportError> {
        let recv = self.conn.accept_uni().await.map_err(conn_err)?;
        Ok(RecvStream::Quic(recv))
    }

    /// Send a datagram.
    pub fn send_datagram(&self, data: Bytes) -> Result<(), TransportError> {
        self.conn.send_datagram(data).map_err(|e| TransportError::SendDatagram(e.to_string()))
    }

    /// Receive a datagram.
    pub async fn recv_datagram(&self) -> Result<Bytes, TransportError> {
        self.conn.read_datagram().await.map_err(conn_err)
    }

    /// Close the connection.
    pub fn close(&self, code: u32, reason: &[u8]) {
        self.conn.close(quinn::VarInt::from_u32(code), reason);
    }

    /// A future resolving when the session ends, carrying the peer's close.
    ///
    /// Borrows nothing and outlives this transport, for the same reason
    /// [`SendStream::stopped`] does: the answer arrives after the call that
    /// wanted it has already returned. A peer refusing a handshake commonly
    /// finishes the control stream first and closes the session a round trip
    /// later, so the caller sees an end-of-stream, hands back an error, and
    /// drops the transport before the code it was refused with ever lands.
    /// Taking this handle *before* the transport is given away is what makes
    /// that code readable at all.
    ///
    /// Holding the future keeps the connection alive; dropping it lets quinn
    /// close as usual.
    pub fn closed(&self) -> impl Future<Output = TransportError> + Send + 'static {
        let conn = self.conn.clone();
        async move { connection_lost(conn.closed().await) }
    }

    /// The certificate chain the peer presented, DER-encoded, leaf first.
    ///
    /// Bytes, and no opinion about them: nothing here parses a certificate,
    /// checks a date, or decides whether a chain is trustworthy, because the
    /// verdict depends on what the caller is measuring. Empty is not an error —
    /// a chain is absent for ordinary reasons, including a handshake that has
    /// not completed.
    ///
    /// A chain that a handshake *failed over* never reaches here, since there
    /// is no connection left to read it off; that is what
    /// [`QuicDialOptions::observing`] is for.
    pub fn peer_certificates(&self) -> Vec<Vec<u8>> {
        peer_certificates(&self.conn)
    }
}

/// Read a quinn connection's peer certificate chain as DER, leaf first.
///
/// Shared with the WebTransport arm, which reaches the same
/// `quinn::Connection` through `wtransport`'s `quic_connection()`. One copy
/// because there is exactly one fragile step here and it should not exist
/// twice: `Connection::peer_identity` is `Option<Box<dyn Any>>`, since quinn is
/// generic over its crypto backend and has no type it could name for every
/// one. The rustls backend documents the concrete type as
/// `Vec<rustls::pki_types::CertificateDer>` and quinn-proto builds exactly
/// that, so the downcast is correct — and it is checked by nothing at compile
/// time, so a quinn release that changed the type would turn this into a
/// permanently empty chain rather than a build failure. That is what
/// `tests/the_peer_certificate_chain_reaches_the_caller.rs` is for: it asserts
/// the bytes handed back are the server's own certificate, byte for byte, so
/// the silent version of that break cannot pass.
///
/// **Bytes, and no opinion about them.** Nothing here parses a certificate,
/// checks a date, or decides whether a chain is trustworthy. A verdict depends
/// on what the caller is measuring — a conformance probe grading a public relay
/// wants "does this chain reach a public root", an operator on a private CA
/// wants the opposite — and a library that guessed would be wrong for one of
/// them while looking authoritative to both. The rule that keeps this honest:
/// the transport reports what the peer sent, the caller decides what it means.
///
/// Empty is not an error and is never reported as one. A chain is absent for
/// ordinary reasons — the handshake has not completed, the peer authenticated
/// by some other means, the session was resumed without one — and none of them
/// are faults this connection can do anything about. A caller that needs the
/// distinction between "no chain" and "a chain we could not read" is asking a
/// question the `Any` boundary above cannot answer anyway.
///
/// The returned `Vec<Vec<u8>>` owns its bytes rather than borrowing the
/// connection's, which costs a copy per certificate and buys the thing callers
/// actually need: a chain that outlives the connection it came from. A probe
/// records the certificate and then closes the connection immediately, so a
/// borrowed chain would have to be interpreted before the peer is released —
/// exactly the ordering constraint this API exists to avoid imposing.
pub(crate) fn peer_certificates(conn: &quinn::Connection) -> Vec<Vec<u8>> {
    conn.peer_identity()
        .and_then(|identity| {
            identity.downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>().ok()
        })
        .map(|chain| chain.iter().map(|der| der.as_ref().to_vec()).collect())
        .unwrap_or_default()
}

/// Convert a quinn connection error to a TransportError.
fn conn_err(e: quinn::ConnectionError) -> TransportError {
    TransportError::Connection(e.to_string())
}

// ── From impls for quinn error types ────────────────────────

impl From<quinn::ConnectionError> for TransportError {
    fn from(e: quinn::ConnectionError) -> Self {
        TransportError::Connection(e.to_string())
    }
}

/// Take a handshake failure apart into codes plus prose.
///
/// The prose is quinn's own `Display`, unchanged, so nothing that reads the
/// message loses anything by this; the codes are otherwise recoverable only by
/// finding digits inside that message.
///
/// The three variants that carry a number are the three that matter to a
/// conformance report: a peer's `CONNECTION_CLOSE`, our own stack's transport
/// error (which is where a locally-detected certificate failure lands), and an
/// application close. The rest — a timeout, a reset, a version mismatch — are
/// findings with genuinely no code in them, and inventing one would be worse
/// than `None`.
pub(crate) fn handshake_failure(e: &quinn::ConnectionError) -> super::HandshakeFailure {
    let reason = e.to_string();
    match e {
        quinn::ConnectionError::TransportError(inner) => {
            super::HandshakeFailure::transport(u64::from(inner.code), reason)
        }
        quinn::ConnectionError::ConnectionClosed(close) => {
            super::HandshakeFailure::transport(u64::from(close.error_code), reason)
        }
        quinn::ConnectionError::ApplicationClosed(close) => {
            super::HandshakeFailure::application(close.error_code.into_inner(), reason)
        }
        _ => super::HandshakeFailure::bare(reason),
    }
}

/// A lost connection, keeping the peer's close code where it named one.
///
/// Both stream error enums render `ConnectionLost` as the two words "connection
/// lost" and drop the cause, so a session a relay ended deliberately — with a
/// MoQT error code, and often a reason phrase saying why — reaches a caller as
/// a sentence carrying neither. This reads them off the value instead.
///
/// Only `ApplicationClosed` carries an application code. A timeout, a stateless
/// reset or a local close have genuinely no such number, and those keep
/// quinn's own message.
fn connection_lost(e: quinn::ConnectionError) -> TransportError {
    match &e {
        quinn::ConnectionError::ApplicationClosed(close) => TransportError::SessionClosed {
            code: close.error_code.into_inner(),
            reason: e.to_string(),
        },
        _ => TransportError::Connection(e.to_string()),
    }
}

impl From<quinn::WriteError> for TransportError {
    /// `Stopped` keeps the peer's application error code as a typed
    /// [`TransportError::Stopped`] so a forwarder can mirror it; every
    /// other cause collapses to a message.
    fn from(e: quinn::WriteError) -> Self {
        match e {
            quinn::WriteError::Stopped(code) => TransportError::Stopped(code.into_inner()),
            quinn::WriteError::ConnectionLost(lost) => connection_lost(lost),
            other => TransportError::Write(other.to_string()),
        }
    }
}

impl From<quinn::ReadError> for TransportError {
    /// `Reset` keeps the peer's application error code as a typed
    /// [`TransportError::StreamReset`] so a forwarder can mirror it;
    /// every other cause collapses to a message.
    fn from(e: quinn::ReadError) -> Self {
        match e {
            quinn::ReadError::Reset(code) => TransportError::StreamReset(code.into_inner()),
            quinn::ReadError::ConnectionLost(lost) => connection_lost(lost),
            other => TransportError::Read(other.to_string()),
        }
    }
}

impl From<quinn::ReadExactError> for TransportError {
    fn from(e: quinn::ReadExactError) -> Self {
        match e {
            quinn::ReadExactError::ReadError(inner) => inner.into(),
            other => TransportError::Read(other.to_string()),
        }
    }
}

impl From<quinn::ConnectError> for TransportError {
    fn from(e: quinn::ConnectError) -> Self {
        TransportError::Connect(e.to_string())
    }
}

impl From<quinn::ClosedStream> for TransportError {
    fn from(_e: quinn::ClosedStream) -> Self {
        TransportError::StreamClosed
    }
}

impl From<quinn::SendDatagramError> for TransportError {
    fn from(e: quinn::SendDatagramError) -> Self {
        TransportError::SendDatagram(e.to_string())
    }
}

// ---------------------------------------------------------------------------
// Dialling
// ---------------------------------------------------------------------------

/// How a QUIC dial is configured, independent of any draft.
///
/// `alpn` is a list because ALPN is: one handshake offers several protocols and
/// the server picks, which is how a caller that does not know a peer's draft
/// finds out without dialling once per candidate.
pub struct QuicDialOptions {
    /// Skip TLS certificate verification. Testing only.
    pub skip_cert_verification: bool,
    /// Additional CA certificates to trust, DER-encoded, on top of the bundled
    /// Mozilla roots every dial starts from, on either transport.
    pub ca_certs: Vec<Vec<u8>>,
    /// ALPN protocols to offer, in preference order.
    ///
    /// [`dial_quic`] returns the one the server selected. An empty list offers
    /// nothing and is refused by any peer that requires ALPN, which every MoQT
    /// relay does.
    ///
    /// A WebTransport dial ignores this field: that session is HTTP/3 by
    /// definition and offers `h3` alone, so the protocol name a WebTransport
    /// session negotiates is `WT-Available-Protocols` and not this. See
    /// [`wt_protocols`](Self::wt_protocols). Everything else here applies to
    /// both transports.
    pub alpn: Vec<Vec<u8>>,
    /// MOQT protocol identifiers to offer in the `WT-Available-Protocols`
    /// header of a WebTransport dial, in preference order.
    ///
    /// WebTransport's answer to ALPN, and the reason a MoQT draft can be
    /// negotiated over it at all. Drafts 15 and later state it in one sentence:
    /// "MOQT uses ALPN in QUIC and `WT-Available-Protocols` in WebTransport
    /// (\[WebTransport\], Section 3.3) to perform version negotiation" —
    /// draft-15 cites Section 3.4 of the same document and is otherwise
    /// word-for-word. Drafts 18 through 20 add the client's half of it: "The
    /// client includes MOQT protocol identifiers in the WT-Available-Protocols
    /// header". The identifiers are the ALPN names: `moqt-15` … `moqt-20`.
    ///
    /// Empty for drafts 07 through 14, which predate the header and settle
    /// their version in CLIENT_SETUP instead. Empty is not the same as absent
    /// by accident: a server that implements the negotiation and receives no
    /// offer has nothing to select, and may reject the session outright.
    /// imquic does, in as many words — "No WebTransport protocol offered".
    ///
    /// Ignored by a QUIC dial, where [`alpn`](Self::alpn) carries the same
    /// names.
    ///
    /// # Reading the answer needs a patched `wtransport`
    ///
    /// A server names its choice in a `WT-Protocol` response header, and
    /// upstream `wtransport` 0.7 drops the CONNECT response once it has judged
    /// the status code. `Transport::wt_protocol` reads it — spelled as code
    /// because it exists only behind this crate's `wt-protocol` feature, and a
    /// link to it would be broken in every build without that feature. The
    /// feature requires the patch in `moqtap/vendor/wtransport` and does not
    /// build without it.
    ///
    /// Without that feature an accepted session says only that the server took
    /// one of the offers or ignored the header, and only a *rejected* one is
    /// conclusive — conclusive, then, about every identifier offered.
    pub wt_protocols: Vec<Vec<u8>>,
    /// Called with the peer's certificate chain during the handshake, **before
    /// it is judged** — so it runs even for a chain that is about to be
    /// rejected, which is the case it exists for. See [`CertificateHook`].
    pub on_peer_certificates: Option<CertificateHook>,
    /// Restrict the TLS 1.3 cipher suites offered, by IANA codepoint.
    ///
    /// `None` offers the crypto provider's full set, which is what an ordinary
    /// client does and what every caller but a measuring one wants.
    ///
    /// `Some` exists because **the negotiated suite cannot be read back**.
    /// quinn's `HandshakeData` carries the ALPN and the server name and nothing
    /// else, and rustls does not surface the suite through it — so the only way
    /// to learn which suite a peer accepts is to offer exactly one and see
    /// whether the handshake completes. A successful dial *is* the measurement.
    ///
    /// Codepoints rather than a rustls enum so that a rustls upgrade cannot
    /// change this crate's public API. The three TLS 1.3 suites are `0x1301`
    /// AES-128-GCM-SHA256, `0x1302` AES-256-GCM-SHA384 and `0x1303`
    /// CHACHA20-POLY1305-SHA256. A codepoint the provider does not have is
    /// [`DialError::TlsConfig`] rather than a silent omission, because silently
    /// offering fewer suites than asked would make every answer a false
    /// negative.
    ///
    /// Excluding `0x1301` is allowed, and is the interesting case. QUIC's
    /// Initial packets must use AES-128-GCM and normally that makes such an
    /// offer unbuildable; the initial keys are taken from the default provider
    /// separately so that only the *traffic* suites are restricted.
    ///
    /// Not honoured by `webtransport::dial_webtransport_to`, which reaches
    /// `wtransport`'s builder and cannot supply a separate initial suite
    /// through it. Spelled as code and not as a link on purpose: that module is
    /// behind the `webtransport` feature, and `just doc-check` builds these
    /// docs with the feature off.
    pub cipher_suites: Option<Vec<u16>>,
}

impl QuicDialOptions {
    /// Options offering `alpn`, verifying certificates against the bundled
    /// Mozilla roots, observing nothing.
    ///
    /// A constructor and not a `Default` because there is no sensible default
    /// ALPN: an empty list is refused by every MoQT relay, so a
    /// `QuicDialOptions::default()` would be a value whose only outcome is TLS
    /// alert 120 — which in a conformance report reads as a defect in the
    /// relay rather than in the caller. Naming the offer is the one thing a
    /// dial cannot do without.
    ///
    /// It is also the base for functional update, which is how the fields
    /// below stay additive:
    ///
    /// ```ignore
    /// QuicDialOptions { skip_cert_verification: true, ..QuicDialOptions::new(alpn) }
    /// ```
    pub fn new(alpn: Vec<Vec<u8>>) -> Self {
        Self {
            skip_cert_verification: false,
            ca_certs: Vec::new(),
            alpn,
            wt_protocols: Vec::new(),
            on_peer_certificates: None,
            cipher_suites: None,
        }
    }

    /// Accept any certificate. Testing only — see
    /// [`skip_cert_verification`](Self::skip_cert_verification).
    pub fn insecure(mut self, yes: bool) -> Self {
        self.skip_cert_verification = yes;
        self
    }

    /// Trust these DER-encoded CAs on top of the bundled roots.
    pub fn ca_certs(mut self, certs: Vec<Vec<u8>>) -> Self {
        self.ca_certs = certs;
        self
    }

    /// Observe the peer's certificate chain, accepted or not.
    ///
    /// [`CertificateLog`] is the collector most callers want:
    ///
    /// ```ignore
    /// let log = CertificateLog::new();
    /// let result = dial_quic_to(&target, &QuicDialOptions::new(alpn).observing(log.hook())).await;
    /// let chain = log.chain();
    /// ```
    pub fn observing(mut self, hook: CertificateHook) -> Self {
        self.on_peer_certificates = Some(hook);
        self
    }

    /// Offer only these cipher suites, by IANA codepoint. See
    /// [`cipher_suites`](Self::cipher_suites).
    pub fn offering_cipher_suites(mut self, suites: Vec<u16>) -> Self {
        self.cipher_suites = Some(suites);
        self
    }

    /// Offer these MOQT protocol identifiers to a WebTransport dial. See
    /// [`wt_protocols`](Self::wt_protocols).
    pub fn offering_wt_protocols(mut self, protocols: Vec<Vec<u8>>) -> Self {
        self.wt_protocols = protocols;
        self
    }
}

/// The TLS 1.3 cipher suites, as IANA codepoints.
///
/// The whole set: TLS 1.3 defines five and rustls implements the three that
/// QUIC can use. Named here so a caller enumerating support does not have to
/// hardcode the numbers, and so [`show_cipher_suite`] and this list cannot
/// drift apart.
pub const TLS13_CIPHER_SUITES: [u16; 3] = [0x1301, 0x1302, 0x1303];

/// The IANA name of a TLS 1.3 cipher suite codepoint.
///
/// Returns `None` for anything outside [`TLS13_CIPHER_SUITES`] rather than
/// inventing a label, so an unknown number is reported as the number.
pub fn show_cipher_suite(code: u16) -> Option<&'static str> {
    match code {
        0x1301 => Some("TLS_AES_128_GCM_SHA256"),
        0x1302 => Some("TLS_AES_256_GCM_SHA384"),
        0x1303 => Some("TLS_CHACHA20_POLY1305_SHA256"),
        _ => None,
    }
}

/// Where packets go, and whose certificate to expect when they arrive.
///
/// Two fields and not one `host:port` string, because they are two different
/// things and a public relay is where that stops being pedantry. The socket
/// layer needs an address it can send to; the TLS layer needs the name a
/// certificate was issued for. Deriving the second from the first — which is
/// what a single string forces — leaves only bad options: dial the hostname
/// and `parse::<SocketAddr>()` rejects it, or resolve first and then validate
/// a public relay's certificate against an IP literal that no CA ever put in
/// a SAN. [`dial_quic`] is where both are avoided.
pub struct QuicTarget {
    /// The address packets are sent to. Already resolved — nothing in this
    /// module does DNS on it.
    pub addr: SocketAddr,
    /// The name offered in SNI and validated against the server's certificate.
    ///
    /// An IP literal is legal and is what a loopback peer holding an IP-SAN
    /// certificate wants; a hostname is what a public relay wants. Keeping it
    /// separate is what lets one caller ask for both against one address.
    pub server_name: String,
}

/// Why a QUIC dial did not produce a connection.
///
/// Separate from [`TransportError`] so the failures that happen before any
/// packet is sent — a bad address, a socket this machine would not open, a TLS
/// config it rejects — stay distinguishable from a peer that would not talk
/// to us. [`DialError::phase`] is that distinction as a value.
///
/// # Why there is a variant for a socket that would not open
///
/// A bind this machine refused is this side's failure, and the type is what has
/// to say so. Folding it into [`InvalidAddress`](Self::InvalidAddress) leaves
/// the message as the only thing telling the two apart — a substring test
/// wearing a type's clothes. A consumer reading it that way recovers "this
/// machine has no IPv6 stack" only where the prose happens to contain `could
/// not bind`, and files the result at whichever phase the *caller* named, which
/// for a single call to [`dial_quic_to`] is one word for four stages: a failed
/// v6 bind then publishes as a relay that failed a QUIC handshake, on a dial
/// where no packet left the machine.
///
/// The WebTransport arm offers no such substring to find. `wtransport`'s
/// endpoint constructor binds the socket too and its failure carries no `could
/// not bind` in the message, so a `TransportError` there reaches
/// [`ErrorCause::Transport`](crate::dispatch::ErrorCause::Transport) through a
/// draft's `ConnectionError`, and `is_local` answers **false** for it — a
/// socket this machine could not open, filed against the peer. Both arms raise
/// this variant.
///
/// # Why it goes no further than this type
///
/// The fourteen `From<DialError> for ConnectionError` impls map this variant
/// onto `ConnectionError::InvalidAddress`, which is one of the variants the
/// facade reads as [`ErrorCause::Facade`](crate::dispatch::ErrorCause::Facade),
/// and with it `is_local() == true` — the right answer for a failure this side
/// decided. Splitting it further there would add public variants for a
/// distinction no caller on that path reads: a draft `Connection` is built by a
/// caller who named a `host:port`, not by one measuring which stage of a dial
/// died. The reader of the distinction is a caller of [`dial_quic_to`], and it
/// reads it off this type directly.
#[derive(Debug, thiserror::Error)]
pub enum DialError {
    /// `addr` is not a `host:port` this machine can resolve to a socket address.
    #[error("invalid address: {0}")]
    InvalidAddress(String),
    /// A local socket could not be opened to send from.
    ///
    /// Nothing about the target: the address is fine and this machine would not
    /// give us a socket to reach it with. The common cause by a distance is
    /// dialling a v6 address from a host or container with no IPv6 stack, which
    /// is a routine outcome for anything that enumerates both families of a
    /// dual-stack name — and a fact about the dialler, never about the peer.
    #[error("local socket error: {0}")]
    LocalSocket(String),
    /// The TLS client configuration could not be built.
    #[error("TLS configuration error: {0}")]
    TlsConfig(String),
    /// The dial itself failed.
    #[error(transparent)]
    Transport(#[from] TransportError),
}

/// Which stage of a dial a [`DialError`] came from.
///
/// A dial is not one event. [`dial_quic_to`] builds a TLS configuration, opens a
/// local socket, asks quinn to start a connection, and only then sends a packet;
/// the four fail for unrelated reasons and only the last of them involves the
/// peer at all. This is that sequence as a value, so a caller can switch on it
/// instead of reading the message a variant renders.
///
/// # The caller cannot supply this itself
///
/// It knows which *call* it made, not which stage inside the call died — and
/// the four stages above live inside one call. A probe recording "handshake"
/// for every failure of `dial_quic_to` is not being careless; it has nothing
/// finer to say until this exists. The one thing it does know that this cannot
/// is which transport it was dialling, which is why
/// [`Handshake`](Self::Handshake) does not distinguish a QUIC handshake from a
/// WebTransport CONNECT: both are a peer answering, and only the caller knows
/// which it asked.
///
/// # Exactly one of these means the peer was involved
///
/// [`Handshake`](Self::Handshake), and [`DialError::is_local`] is that sentence
/// as a predicate. The other four are decided on this machine with nothing on
/// the wire, so a failure carrying one of them can never be evidence about the
/// peer — which is the direction this distinction is load-bearing in. The
/// converse is weaker and deliberately not claimed: a handshake that timed out
/// is not proof of anything the peer did either, only that the machine got as
/// far as sending.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DialPhase {
    /// Turning what the caller named into somewhere to send — parsing a
    /// `host:port`, resolving it, finding it resolved to nothing.
    Address,
    /// Opening a local socket to send from. See [`DialError::LocalSocket`].
    LocalSocket,
    /// Building the TLS client configuration: a `ca_certs` entry that is not a
    /// certificate, a cipher suite the crypto provider does not implement.
    TlsConfig,
    /// The stack refusing to start the connection — a server name rustls will
    /// not accept, a remote address quinn will not dial. Nothing was sent.
    Connect,
    /// The handshake, and the only phase in which the peer is involved.
    Handshake,
}

impl DialError {
    /// Which stage of the dial this failure came from.
    ///
    /// Total and structural: every variant answers, and no arm reads a message.
    /// [`DialError::Transport`] splits on whether the transport error is the
    /// typed [`TransportError::Handshake`] — which by construction exists only
    /// where a peer answered — so everything else under it is the stack
    /// declining to start, which is [`DialPhase::Connect`].
    pub fn phase(&self) -> DialPhase {
        match self {
            DialError::InvalidAddress(_) => DialPhase::Address,
            DialError::LocalSocket(_) => DialPhase::LocalSocket,
            DialError::TlsConfig(_) => DialPhase::TlsConfig,
            DialError::Transport(TransportError::Handshake(_)) => DialPhase::Handshake,
            DialError::Transport(_) => DialPhase::Connect,
        }
    }

    /// Whether the dial failed **before a packet left this machine**.
    ///
    /// True for everything but [`DialPhase::Handshake`]. The name matches
    /// [`AnyConnectionError::is_local`](crate::dispatch::AnyConnectionError::is_local),
    /// which answers the same question for everything after the dial, and it is
    /// worth being exact about what each half of the answer buys:
    ///
    /// - **`true` is a guarantee.** Nothing was sent, so the failure cannot be
    ///   evidence about the peer, and anything that publishes it as such is
    ///   publishing a finding that never happened.
    /// - **`false` is not the opposite guarantee.** It says the machine got as
    ///   far as sending, and a handshake can still fail for reasons that are
    ///   nobody's fault in particular — a timeout, a network that dropped the
    ///   packets. Read [`TransportError::Handshake`]'s codes for what the peer
    ///   actually said; this only says whether there was a peer to ask.
    pub fn is_local(&self) -> bool {
        self.phase() != DialPhase::Handshake
    }
}

/// The one place either transport decides what a server certificate is checked
/// against.
///
/// Shared, and that is the whole point of it. Two transports answering this
/// question apart from each other answer it differently: a `RootCertStore`
/// seeded from the `webpki-roots` bundle with `ca_certs` added to it on one
/// side, `wtransport`'s `with_native_certs()` — the *OS* trust store, which
/// never sees `ca_certs` — on the other. Two consequences, both of which a
/// conformance run publishes as facts about the relay:
///
/// - The bundled Mozilla set and a machine's own set are not the same set. They
///   diverge on newly-added roots, on roots a distribution has retired early,
///   and on whatever a corporate MITM appliance installed. A relay would
///   therefore pass over QUIC and fail over WebTransport with nothing about the
///   relay differing between the two dials.
/// - A caller supplying a private CA would have it honoured on one transport
///   and silently dropped on the other. Not an error, not a warning — a
///   handshake failure that looks exactly like a relay presenting a bad chain.
///
/// Bundled roots for both, rather than native for both, because a published
/// measurement has to be reproducible: `webpki-roots` is a fixed set compiled
/// into the binary, so two runs on two machines validate against the same
/// anchors and any difference in the outcome is a difference in the relay. The
/// cost is that a peer whose chain the operator trusts only via the OS store is
/// not trusted here — that operator passes the CA in `ca_certs`, which is what
/// the field is for and why it reaches both transports.
///
/// `alpn` is a parameter and not read off `options` because it is the one part
/// of the handshake the two transports do not share: a QUIC dial offers the
/// draft ALPNs it wants the server to choose between, a WebTransport session
/// offers `h3` and nothing else. Everything a certificate is judged by comes
/// from `options`.
///
/// Returns [`DialError::TlsConfig`] for a `ca_certs` entry that is not a
/// parseable certificate, and for a crypto provider without the AES-128-GCM
/// suite QUIC's initial packets are obliged to use.
///
/// # The initial suite is separate from the offered suites
///
/// QUIC encrypts its Initial packets with AES-128-GCM and has no say in the
/// matter (RFC 9001 §5.2), which normally makes that suite impossible to leave
/// out of an offer — and therefore makes "does this peer accept *only*
/// ChaCha20" unaskable. `QuicClientConfig::with_initial` exists for exactly
/// this: it takes the initial keys from one suite and lets the TLS config offer
/// another. So when [`QuicDialOptions::cipher_suites`] excludes AES-128-GCM,
/// the initial suite is taken from the process default provider and only the
/// *traffic* suites are restricted.
pub(crate) fn client_config(
    options: &QuicDialOptions,
    alpn: Vec<Vec<u8>>,
) -> Result<quinn::ClientConfig, DialError> {
    use std::sync::Arc;

    let tls_config = Arc::new(rustls_client_config(options, alpn)?);

    let has_initial = tls_config
        .crypto_provider()
        .cipher_suites
        .iter()
        .any(|cs| cs.suite() == rustls::CipherSuite::TLS13_AES_128_GCM_SHA256);

    let quic_config = if has_initial {
        quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .map_err(|e| DialError::TlsConfig(format!("{e}")))?
    } else {
        quinn::crypto::rustls::QuicClientConfig::with_initial(tls_config, initial_suite()?)
            .map_err(|e| DialError::TlsConfig(format!("{e}")))?
    };
    Ok(quinn::ClientConfig::new(Arc::new(quic_config)))
}

/// The AES-128-GCM keys QUIC's Initial packets require, from the default
/// provider.
///
/// Read from the process default rather than from the dial's own (possibly
/// restricted) provider, because the whole point of reaching this function is
/// that the dial's provider deliberately does not have it.
fn initial_suite() -> Result<rustls::quic::Suite, DialError> {
    default_provider()
        .cipher_suites
        .iter()
        .find(|cs| cs.suite() == rustls::CipherSuite::TLS13_AES_128_GCM_SHA256)
        .and_then(|cs| cs.tls13())
        .and_then(|cs| cs.quic_suite())
        .ok_or_else(|| {
            DialError::TlsConfig(
                "the crypto provider has no TLS13_AES_128_GCM_SHA256, which QUIC's initial \
                 packets require"
                    .to_string(),
            )
        })
}

/// The process-wide crypto provider, or `ring` if none was installed.
fn default_provider() -> std::sync::Arc<rustls::crypto::CryptoProvider> {
    rustls::crypto::CryptoProvider::get_default()
        .cloned()
        .unwrap_or_else(|| std::sync::Arc::new(rustls::crypto::ring::default_provider()))
}

/// The rustls half of [`client_config`], before quinn wraps it.
///
/// Split out for the WebTransport dial, which cannot use the quinn form: the
/// only `wtransport` builder state carrying `dns_resolver` — the hook that lets
/// a caller choose which address a session goes to — is reached through
/// `with_custom_tls`, which takes a `rustls::ClientConfig`. The state that
/// accepts a ready-made quinn config has no such hook.
///
/// Everything that decides a certificate verdict lives here, so both transports
/// still get it from one place — including
/// [`on_peer_certificates`](QuicDialOptions::on_peer_certificates), which is
/// installed inside the verifier because that is the only place the chain
/// exists when a handshake is going to fail. Reading it off the finished
/// connection — what [`super::Transport::peer_certificates`] does — works only
/// when there *is* a finished connection, and the certificates worth reporting
/// on are disproportionately the ones that stopped a handshake from finishing.
pub(crate) fn rustls_client_config(
    options: &QuicDialOptions,
    alpn: Vec<Vec<u8>>,
) -> Result<rustls::ClientConfig, DialError> {
    use std::sync::Arc;

    // The verifier the caller's options ask for, before any recording.
    let verifier: Arc<dyn rustls::client::danger::ServerCertVerifier> =
        if options.skip_cert_verification {
            Arc::new(SkipVerification::new())
        } else {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            for der in &options.ca_certs {
                roots
                    .add(rustls::pki_types::CertificateDer::from(der.clone()))
                    .map_err(|e| DialError::TlsConfig(format!("bad CA cert: {e}")))?;
            }
            rustls::client::WebPkiServerVerifier::builder(Arc::new(roots))
                .build()
                .map_err(|e| DialError::TlsConfig(format!("{e}")))?
        };

    // Wrapping is what keeps observing orthogonal to judging: the decorator
    // copies the chain and then hands the same arguments to the verifier that
    // would have run anyway, so an observed dial and an unobserved one reach
    // identical verdicts. Anything else would make the act of measuring change
    // the measurement.
    let verifier = match &options.on_peer_certificates {
        Some(hook) => Arc::new(ObservingVerifier { inner: verifier, hook: Arc::clone(hook) })
            as Arc<dyn rustls::client::danger::ServerCertVerifier>,
        None => verifier,
    };

    // `builder()` when nothing is restricted, so the default path is byte for
    // byte what it always was; the provider form only when a caller is
    // measuring. TLS 1.3 is pinned explicitly there because that builder does
    // not default to it and QUIC permits nothing else.
    let builder = match &options.cipher_suites {
        None => rustls::ClientConfig::builder(),
        Some(wanted) => {
            rustls::ClientConfig::builder_with_provider(Arc::new(restricted_provider(wanted)?))
                .with_protocol_versions(&[&rustls::version::TLS13])
                .map_err(|e| DialError::TlsConfig(format!("{e}")))?
        }
    };

    let mut tls_config =
        builder.dangerous().with_custom_certificate_verifier(verifier).with_no_client_auth();

    tls_config.alpn_protocols = alpn;
    Ok(tls_config)
}

/// The default provider with its cipher suites narrowed to `wanted`.
///
/// A requested suite the provider does not implement is an error and not a
/// silent omission. Offering fewer suites than asked would make a refusal
/// indistinguishable from a suite that was never on the wire, which turns every
/// negative result into a possible false one — and this field exists only to
/// produce negative results that mean something.
fn restricted_provider(wanted: &[u16]) -> Result<rustls::crypto::CryptoProvider, DialError> {
    let base = default_provider();

    let mut suites = Vec::with_capacity(wanted.len());
    for code in wanted {
        let found = base.cipher_suites.iter().find(|cs| u16::from(cs.suite()) == *code);
        match found {
            Some(cs) => suites.push(*cs),
            None => {
                let name = show_cipher_suite(*code).unwrap_or("unknown");
                return Err(DialError::TlsConfig(format!(
                    "the crypto provider does not implement cipher suite {code:#06x} ({name})"
                )));
            }
        }
    }
    if suites.is_empty() {
        return Err(DialError::TlsConfig(
            "an empty cipher suite list offers nothing and no peer can answer it".to_string(),
        ));
    }

    Ok(rustls::crypto::CryptoProvider { cipher_suites: suites, ..(*base).clone() })
}

/// Dial one already-resolved address, and report which ALPN the server chose.
///
/// This is the whole dial with nothing decided for the caller: one address,
/// one server name, one ALPN offer, one answer. [`dial_quic`] is the
/// convenience wrapper that resolves a `host:port` and picks an address; a
/// caller measuring *which* address or *which* name a relay answers on wants
/// this one, so that each attempt fails on its own and is recorded on its own.
///
/// The second return value is the protocol the server chose from `options.alpn`,
/// `None` if it selected none.
/// [`DraftVersion::from_alpn`](moqtap_codec::version::DraftVersion::from_alpn)
/// names a draft for five of the six; drafts 07-14 share `moq-00` and settle
/// their version in CLIENT_SETUP.
///
/// The endpoint is dropped when the dial returns — quinn keeps the connection's
/// driver alive independently.
pub async fn dial_quic_to(
    target: &QuicTarget,
    options: &QuicDialOptions,
) -> Result<(super::Transport, Option<Vec<u8>>), DialError> {
    let server_addr = target.addr;

    // Built before the socket, so a CA the caller cannot have meant fails
    // without a packet leaving the machine. Through `client_config` and not
    // inline, so that this dial and the WebTransport one agree about the
    // initial cipher suite as well as about certificates.
    let config = client_config(options, options.alpn.clone())?;

    // Bind in the target's address family. A socket bound to `0.0.0.0` cannot
    // send to a v6 peer, and quinn reports that as `invalid remote address` —
    // which reads like the address was malformed when it was only unreachable
    // from the socket we opened. Measured against a dual-stack relay whose
    // first resolved address was v6.
    let bind: SocketAddr = match server_addr {
        SocketAddr::V4(_) => (Ipv4Addr::UNSPECIFIED, 0).into(),
        SocketAddr::V6(_) => (Ipv6Addr::UNSPECIFIED, 0).into(),
    };
    let mut endpoint = quinn::Endpoint::client(bind).map_err(|e| {
        // Not `InvalidAddress` about the *target*: the target is fine and this
        // machine could not open a local socket to reach it. `LocalSocket`
        // keeps that distinction in the type rather than in the message.
        DialError::LocalSocket(format!("could not bind a local {} socket: {e}", family(bind)))
    })?;
    endpoint.set_default_client_config(config);

    let quic = endpoint
        .connect(server_addr, &target.server_name)
        .map_err(TransportError::from)?
        .await
        // Not the blanket `From`, which flattens to a message: this is the one
        // place a peer's refusal is still typed, and a caller measuring *why* a
        // relay refused needs the code rather than a sentence containing it.
        .map_err(|e| TransportError::Handshake(handshake_failure(&e)))?;

    let negotiated = negotiated_alpn(&quic);
    Ok((super::Transport::Quic(QuicTransport::new(quic)), negotiated))
}

/// Resolve `addr` and dial the first address that answers.
///
/// Keeps the signature every draft module's `connect_quic` already calls, so
/// all fourteen reach this resolution without any of them being touched.
///
/// Why it resolves rather than parses: `addr.parse::<SocketAddr>()` accepts
/// numeric literals and nothing else, so every hostname fails with `invalid
/// address: invalid socket address syntax` before a packet is sent — a loopback
/// interop suite passes while every public relay is unreachable. Resolving in
/// the caller is not an answer either: the resolved IP becomes the SNI and the
/// certificate check runs against it. `resolve` hands back the name and the
/// addresses separately, which is what [`QuicTarget`] has two fields for.
///
/// One connection is what this returns, so one is what it looks for; a caller
/// that needs to know an address failed, rather than that some address worked,
/// wants [`dial_quic_to`] per address instead.
pub async fn dial_quic(
    addr: &str,
    options: &QuicDialOptions,
) -> Result<(super::Transport, Option<Vec<u8>>), DialError> {
    let (server_name, addrs) = resolve(addr).await?;

    let mut last: Option<(SocketAddr, DialError)> = None;
    for candidate in addrs {
        let target = QuicTarget { addr: candidate, server_name: server_name.clone() };
        match dial_quic_to(&target, options).await {
            Ok(connected) => return Ok(connected),
            Err(e) => last = Some((candidate, e)),
        }
    }

    match last {
        Some((candidate, e)) => Err(e_at(candidate, e)),
        // `resolve` refuses to return an empty list, so the loop always ran.
        None => Err(DialError::InvalidAddress(format!("{addr} resolved to no addresses"))),
    }
}

/// Name the address a flattened multi-address failure came from.
///
/// `dial_quic` collapses several attempts into one error, which is exactly the
/// lossiness a probe must not have — and is fine here, because a caller of
/// `dial_quic` asked for one connection and not for a measurement. Saying
/// which address produced the surviving error is the least it can do.
///
/// # It must not relabel the phase while it does that
///
/// Every arm returns the variant it was given, and that is a correctness
/// requirement rather than tidiness: [`DialError::phase`] reads the variant, so
/// an arm that rewrote a peer's refusal into a `Connect` in order to prefix the
/// address would make `is_local` answer **true** for a relay that answered a
/// handshake, and would throw that handshake's codes away with it. Prefixing a
/// peer's failure means going inside [`HandshakeFailure`] and prefixing the
/// reason, which keeps its codes as well as its phase.
///
/// [`HandshakeFailure`]: super::HandshakeFailure
fn e_at(addr: SocketAddr, e: DialError) -> DialError {
    match e {
        DialError::InvalidAddress(m) => DialError::InvalidAddress(format!("{addr}: {m}")),
        DialError::LocalSocket(m) => DialError::LocalSocket(format!("{addr}: {m}")),
        DialError::TlsConfig(m) => DialError::TlsConfig(format!("{addr}: {m}")),
        DialError::Transport(TransportError::Handshake(failure)) => {
            DialError::Transport(TransportError::Handshake(super::HandshakeFailure {
                reason: format!("{addr}: {}", failure.reason),
                ..failure
            }))
        }
        DialError::Transport(inner) => {
            DialError::Transport(TransportError::Connect(format!("{addr}: {inner}")))
        }
    }
}

/// Split `host:port` into the name to validate against and every address it
/// resolves to, v4 first.
///
/// v4 first is a preference and not a correctness claim: a v6 attempt on a
/// host without v6 connectivity burns the caller's entire timeout before v4
/// is reached, and this path exists to return one working connection quickly.
/// It is the wrong default for measuring a relay, which is why a probe should
/// enumerate the list itself and dial each address through [`dial_quic_to`]
/// rather than inherit this ordering.
async fn resolve(addr: &str) -> Result<(String, Vec<SocketAddr>), DialError> {
    // A literal is its own answer and its own server name. Loopback peers are
    // dialled this way, and one holding an IP-SAN certificate has to keep
    // validating against the IP — so this cannot be routed through the
    // hostname path even though `lookup_host` would accept it.
    if let Ok(sock) = addr.parse::<SocketAddr>() {
        return Ok((sock.ip().to_string(), vec![sock]));
    }

    let host = host_of(addr)?;
    let mut resolved: Vec<SocketAddr> = tokio::net::lookup_host(addr)
        .await
        .map_err(|e| DialError::InvalidAddress(format!("could not resolve {addr}: {e}")))?
        .collect();

    if resolved.is_empty() {
        return Err(DialError::InvalidAddress(format!("{addr} resolved to no addresses")));
    }
    resolved.sort_by_key(|a| a.is_ipv6());
    Ok((host, resolved))
}

/// The host part of `host:port`, with the port removed and brackets stripped.
///
/// `rsplit_once(':')` alone is wrong for `[::1]:443`: it would cut at the last
/// colon inside the address and hand back `[::1]` including the bracket, which
/// is not a name rustls will accept.
fn host_of(addr: &str) -> Result<String, DialError> {
    if let Some(rest) = addr.strip_prefix('[') {
        return rest
            .split_once(']')
            .map(|(host, _)| host.to_string())
            .ok_or_else(|| DialError::InvalidAddress(format!("unclosed '[' in {addr}")));
    }
    addr.rsplit_once(':')
        .map(|(host, _)| host.to_string())
        .filter(|host| !host.is_empty())
        .ok_or_else(|| DialError::InvalidAddress(format!("{addr} is not host:port")))
}

/// `"IPv4"` or `"IPv6"`, for the one error message that needs to say which.
fn family(addr: SocketAddr) -> &'static str {
    if addr.is_ipv4() {
        "IPv4"
    } else {
        "IPv6"
    }
}

/// The ALPN the server selected, if the handshake recorded one.
fn negotiated_alpn(conn: &quinn::Connection) -> Option<Vec<u8>> {
    conn.handshake_data()?.downcast::<quinn::crypto::rustls::HandshakeData>().ok()?.protocol
}

/// Called with a certificate chain observed during a handshake, DER, leaf
/// first.
///
/// A hook and not a return value because a verifier that is about to reject a
/// certificate has no return path that carries one — it answers with an error,
/// and the bytes it was judging go out of scope. The interesting certificates
/// are exactly the rejected ones, so the observation has to happen where the
/// judging does.
///
/// Two things about where it runs. It is called from inside the TLS handshake,
/// on quinn's connection driver task rather than on the task that called the
/// dial, so a hook that blocks stalls the connection and one that panics
/// unwinds into the driver — keep it to moving bytes somewhere. And
/// [`dial_quic`] calls it once per resolved address it tries, with nothing in
/// the arguments to say which; a caller that needs to attribute a chain to an
/// address should dial each one with [`dial_quic_to`].
pub type CertificateHook = std::sync::Arc<dyn Fn(&[Vec<u8>]) + Send + Sync>;

/// The [`CertificateHook`] most callers want: keep the chain, read it after.
///
/// Shipped rather than left to each caller because the storage behind this hook
/// is the same shared, lock-guarded vector every time, and because it survives
/// cancellation — a dial abandoned by `tokio::time::timeout` still leaves
/// whatever chain it had already seen in the log, where a chain returned
/// alongside the dial's result would be dropped with the future.
#[derive(Clone, Default)]
pub struct CertificateLog(std::sync::Arc<std::sync::Mutex<Vec<Vec<u8>>>>);

impl CertificateLog {
    /// An empty log.
    pub fn new() -> Self {
        Self::default()
    }

    /// The hook to hand to
    /// [`QuicDialOptions::observing`](QuicDialOptions::observing).
    pub fn hook(&self) -> CertificateHook {
        let slot = std::sync::Arc::clone(&self.0);
        std::sync::Arc::new(move |chain: &[Vec<u8>]| {
            if let Ok(mut seen) = slot.lock() {
                *seen = chain.to_vec();
            }
        })
    }

    /// The last chain observed, empty if the handshake never got as far as one.
    ///
    /// Empty therefore means *no certificate was offered* — a refused ALPN, a
    /// dead port, a timeout — and never *the certificate was unreadable*.
    pub fn chain(&self) -> Vec<Vec<u8>> {
        self.0.lock().map(|seen| seen.clone()).unwrap_or_default()
    }
}

impl std::fmt::Debug for CertificateLog {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("CertificateLog").field(&self.chain().len()).finish()
    }
}

/// A verifier that writes down the chain it was shown, then defers to another.
///
/// It exists because the interesting certificates are the rejected ones. A
/// relay with an expired certificate, a private CA, or a name that does not
/// match never completes a handshake, so nothing is left afterwards to read the
/// chain off — and "the handshake failed for a certificate reason" without the
/// certificate is exactly the report a relay operator cannot act on.
///
/// It observes unconditionally and judges not at all. The inner verifier's
/// verdict is returned untouched, so wrapping cannot turn a rejection into an
/// acceptance however the observation goes.
struct ObservingVerifier {
    inner: std::sync::Arc<dyn rustls::client::danger::ServerCertVerifier>,
    hook: CertificateHook,
}

// Hand-written because `rustls::client::danger::ServerCertVerifier` requires
// `Debug` of the verifier, and `#[derive]` would push that requirement onto the
// hook — which would make `CertificateHook` a trait with a `Debug` supertrait
// rather than a closure, for no benefit to anyone but this line.
impl std::fmt::Debug for ObservingVerifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObservingVerifier").field("inner", &self.inner).finish_non_exhaustive()
    }
}

impl rustls::client::danger::ServerCertVerifier for ObservingVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &rustls::pki_types::CertificateDer<'_>,
        intermediates: &[rustls::pki_types::CertificateDer<'_>],
        server_name: &rustls::pki_types::ServerName<'_>,
        ocsp_response: &[u8],
        now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // Observe before judging, so a rejection still leaves the evidence
        // behind. Leaf first, matching what a finished connection reports.
        let mut chain = Vec::with_capacity(1 + intermediates.len());
        chain.push(end_entity.as_ref().to_vec());
        chain.extend(intermediates.iter().map(|der| der.as_ref().to_vec()));
        (self.hook)(&chain);

        self.inner.verify_server_cert(end_entity, intermediates, server_name, ocsp_response, now)
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls12_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        self.inner.verify_tls13_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        self.inner.supported_verify_schemes()
    }
}

/// TLS certificate verifier that skips all verification. Testing only.
#[derive(Debug)]
struct SkipVerification {
    /// The provider whose signature schemes this verifier advertises.
    ///
    /// Held rather than hardcoded because
    /// [`supported_verify_schemes`](SkipVerification::supported_verify_schemes)
    /// is not a claim about what this verifier checks — it checks nothing — but
    /// about what the *ClientHello* offers. See that method for why the
    /// distinction has teeth.
    provider: std::sync::Arc<rustls::crypto::CryptoProvider>,
}

impl SkipVerification {
    /// Use whichever provider this process installed, falling back to the one
    /// this crate compiles with.
    ///
    /// Taking the installed provider rather than naming `ring` unconditionally
    /// keeps the verifier's advertised schemes in step with the schemes the
    /// rest of the handshake was actually built from, however the embedding
    /// binary configured rustls.
    fn new() -> Self {
        Self { provider: default_provider() }
    }
}

impl rustls::client::danger::ServerCertVerifier for SkipVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dcs: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dcs: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    /// Every scheme the active provider can verify.
    ///
    /// This looks like dead weight on a verifier that verifies nothing, and it
    /// is not: rustls sends this list as the ClientHello's
    /// `signature_algorithms` extension, so it decides which certificates a
    /// server is *willing to offer us* — before this verifier is consulted at
    /// all.
    ///
    /// Read off the provider rather than written out by hand, because a
    /// hand-written list omits whatever it forgets — `ECDSA_NISTP521_SHA512` is
    /// the easy one to miss. A relay with a P-521 leaf would then fail
    /// a verification-disabled connection because of what this client offered,
    /// not because of anything wrong with the relay — and for the conformance
    /// probe that consumes this crate, a failure it manufactured itself is the
    /// one result it must never record.
    ///
    /// The provider's own list is the floor, so the offer widens whenever the
    /// provider's does. It is not the ceiling, because it cannot be: `ring`
    /// does not implement P-521 at all, so deferring to it alone still leaves
    /// that certificate unreachable. That constraint does not apply *here* —
    /// this verifier accepts every certificate without looking at it, so a
    /// scheme it could not check is one it never needs to. Advertising a
    /// superset is exactly right for a verifier that verifies nothing, and
    /// would be wrong for any verifier that does.
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        let mut schemes = self.provider.signature_verification_algorithms.supported_schemes();

        // Schemes a server might legitimately sign with that the provider
        // cannot verify. Additive and deduplicated, so a provider that grows
        // support for one of these does not end up offering it twice.
        for extra in [rustls::SignatureScheme::ECDSA_NISTP521_SHA512] {
            if !schemes.contains(&extra) {
                schemes.push(extra);
            }
        }
        schemes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustls::client::danger::ServerCertVerifier;

    /// The list was six schemes written out by hand, and `ECDSA_NISTP521_SHA512`
    /// was not among them. rustls sends it as the ClientHello's
    /// `signature_algorithms`, so the omission decided which certificates a
    /// server would offer — meaning a P-521 relay failed a
    /// verification-disabled dial because of this client rather than because of
    /// anything about the relay.
    #[test]
    fn skipping_verification_still_offers_every_scheme_the_provider_has() {
        let schemes = SkipVerification::new().supported_verify_schemes();

        assert!(
            schemes.contains(&rustls::SignatureScheme::ECDSA_NISTP521_SHA512),
            "P-521 missing from the offer: {schemes:?}"
        );
        // The six that were hardcoded must all survive.
        for required in [
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ] {
            assert!(schemes.contains(&required), "{required:?} missing from {schemes:?}");
        }
    }

    /// A TLS alert is a QUIC code with the top bit set, and both halves matter:
    /// the code is what the wire carried, the alert is what it means.
    #[test]
    fn a_crypto_code_yields_the_alert_it_encodes() {
        // 120 `no_application_protocol` — a relay refusing every draft offered.
        let refused = handshake_failure(&quinn::ConnectionError::TransportError(
            quinn::TransportErrorCode::crypto(120).into(),
        ));
        assert_eq!(refused.code, Some(0x178));
        assert_eq!(refused.tls_alert, Some(120));

        // 45 `certificate_expired` — the live case across the seed fleet.
        let expired = handshake_failure(&quinn::ConnectionError::TransportError(
            quinn::TransportErrorCode::crypto(45).into(),
        ));
        assert_eq!(expired.code, Some(0x12d));
        assert_eq!(expired.tls_alert, Some(45));
    }

    /// Codes outside `0x0100..=0x01ff` are not alerts and must not be reported
    /// as one. `0x178 & 0xff` is a valid alert; `0x10f & 0xff` would be too, and
    /// masking without checking the range is how an application close becomes a
    /// fictional alert in a conformance report.
    #[test]
    fn a_non_crypto_code_names_no_alert() {
        let closed = handshake_failure(&quinn::ConnectionError::ApplicationClosed(
            quinn::ApplicationClose {
                error_code: quinn::VarInt::from_u32(271),
                reason: (&[][..]).into(),
            },
        ));
        assert_eq!(closed.code, Some(271));
        assert_eq!(closed.code_space, Some(super::super::CodeSpace::Application));
        assert_eq!(closed.tls_alert, None, "271 is an application code, not alert 15");

        assert_eq!(super::super::HandshakeFailure::alert_of(0x00ff), None);
        assert_eq!(super::super::HandshakeFailure::alert_of(0x0200), None);
        assert_eq!(super::super::HandshakeFailure::alert_of(0x0100), Some(0));
        assert_eq!(super::super::HandshakeFailure::alert_of(0x01ff), Some(255));
    }

    /// A session a peer ended on purpose keeps the code it ended it with.
    ///
    /// quinn renders `ReadError::ConnectionLost` as the two words "connection
    /// lost", so without the mapping under test this reaches a caller as a
    /// sentence with no code, no reason phrase and nothing to distinguish a
    /// deliberate refusal from a dropped connection. `0x15` is
    /// `VERSION_NEGOTIATION_FAILED`.
    #[test]
    fn a_session_a_peer_closed_keeps_its_code_and_its_reason() {
        let read = TransportError::from(quinn::ReadError::ConnectionLost(
            quinn::ConnectionError::ApplicationClosed(quinn::ApplicationClose {
                error_code: quinn::VarInt::from_u32(0x15),
                reason: (&b"unsupported version"[..]).into(),
            }),
        ));
        let TransportError::SessionClosed { code, .. } = &read else {
            panic!("expected a session close, got {read}");
        };
        assert_eq!(*code, 0x15);
        // Spelled the way every other code this crate reports is spelled, so
        // that a reader parsing the message finds it where it expects to.
        let shown = read.to_string();
        assert!(shown.contains("(code 21)"), "{shown}");
        assert!(shown.contains("unsupported version"), "{shown}");
    }

    /// A connection lost with nothing behind it invents no code.
    ///
    /// A timeout is not a refusal, and reporting one as a close with a code is
    /// the same class of error as reading a TLS alert out of an application
    /// code: a finding that never happened.
    #[test]
    fn a_timeout_is_not_a_close_and_names_no_code() {
        let lost = TransportError::from(quinn::ReadError::ConnectionLost(
            quinn::ConnectionError::TimedOut,
        ));
        assert!(
            matches!(lost, TransportError::Connection(_)),
            "a timeout carries no application code, got {lost}"
        );
    }

    fn measuring(suites: Vec<u16>) -> QuicDialOptions {
        QuicDialOptions::new(vec![b"h3".to_vec()]).insecure(true).offering_cipher_suites(suites)
    }

    /// The claim `cipher_suites` rests on, and the one that is not obvious.
    ///
    /// QUIC's Initial packets must use AES-128-GCM, so a config that does not
    /// offer it would normally be unbuildable — which would make "does this
    /// peer accept *only* ChaCha20" an unaskable question. `with_initial`
    /// separates the two, and this asserts it actually works rather than
    /// trusting the doc comment.
    #[test]
    fn a_suite_offer_excluding_aes128_still_builds() {
        for suite in [0x1303, 0x1302] {
            client_config(&measuring(vec![suite]), vec![b"h3".to_vec()])
                .unwrap_or_else(|e| panic!("offering only {suite:#06x} should build: {e}"));
        }
    }

    /// Every suite this crate names must be one the provider actually has,
    /// or an enumeration built from the list reports false negatives.
    #[test]
    fn every_named_suite_is_offerable_on_its_own() {
        for suite in TLS13_CIPHER_SUITES {
            let name = show_cipher_suite(suite).expect("a named suite has a name");
            client_config(&measuring(vec![suite]), vec![b"h3".to_vec()])
                .unwrap_or_else(|e| panic!("{name} ({suite:#06x}) is not offerable: {e}"));
        }
    }

    /// A suite the provider lacks must be an error, never a quiet omission:
    /// offering fewer suites than asked turns a refusal into a false negative.
    #[test]
    fn an_unavailable_suite_is_refused_rather_than_dropped() {
        // 0x1304 is TLS_AES_128_CCM_SHA256 — real, and not in `ring`.
        let err = client_config(&measuring(vec![0x1301, 0x1304]), vec![b"h3".to_vec()])
            .expect_err("an unimplemented suite must not be silently dropped");
        assert!(format!("{err}").contains("1304"), "the error should name the suite: {err}");

        let empty = client_config(&measuring(Vec::new()), vec![b"h3".to_vec()])
            .expect_err("an empty offer cannot be answered by anyone");
        assert!(format!("{empty}").contains("empty"), "{empty}");
    }

    /// The default path is unrestricted, and stays the path everything but a
    /// measurement takes.
    #[test]
    fn no_restriction_offers_the_whole_provider() {
        let options = QuicDialOptions::new(vec![b"h3".to_vec()]).insecure(true);
        assert!(options.cipher_suites.is_none());
        let config = rustls_client_config(&options, vec![b"h3".to_vec()]).expect("build");
        assert!(
            config.crypto_provider().cipher_suites.len() >= TLS13_CIPHER_SUITES.len(),
            "the unrestricted offer should carry at least the TLS 1.3 suites"
        );
    }

    /// Every variant names a phase, and only one of them says a peer was there.
    ///
    /// The table is written out rather than derived so that a variant added to
    /// [`DialError`] arrives here as a missing row rather than as a silent
    /// answer — `phase` matches exhaustively, so the compiler catches the
    /// *variant*, and this catches the *claim* about which side it belongs to.
    #[test]
    fn every_dial_failure_names_its_phase_and_which_side_it_is() {
        let cases = [
            (DialError::InvalidAddress("x".into()), DialPhase::Address, true),
            (DialError::LocalSocket("x".into()), DialPhase::LocalSocket, true),
            (DialError::TlsConfig("x".into()), DialPhase::TlsConfig, true),
            (DialError::Transport(TransportError::Connect("x".into())), DialPhase::Connect, true),
            (
                DialError::Transport(TransportError::Handshake(
                    super::super::HandshakeFailure::bare("x".into()),
                )),
                DialPhase::Handshake,
                false,
            ),
        ];
        for (err, phase, local) in cases {
            assert_eq!(err.phase(), phase, "{err}");
            assert_eq!(err.is_local(), local, "{err}");
        }
    }

    /// A socket this machine would not open is not an invalid address.
    ///
    /// They are separate variants, so a consumer that needs the difference
    /// reads it off the type rather than by finding `could not bind` inside the
    /// prose. The message still carries those words for a human reader; it is
    /// not where the answer lives.
    #[test]
    fn a_failed_bind_is_this_machines_and_not_the_targets() {
        let bind = DialError::LocalSocket("could not bind a local IPv6 socket: oh no".into());
        assert_eq!(bind.phase(), DialPhase::LocalSocket);
        assert!(bind.is_local());
        assert!(bind.to_string().contains("could not bind a local IPv6 socket"), "{bind}");

        // And the target being unusable is still its own answer.
        let target = DialError::InvalidAddress("relay.example:443 is not host:port".into());
        assert_eq!(target.phase(), DialPhase::Address);
    }

    /// Flattening several addresses into one error must not relabel the phase.
    ///
    /// `e_at` prefixes the address onto the error it returns, and has to do
    /// that without rewriting a `Transport` failure into a `Connect`: the
    /// variant decides the phase, so flattening would throw the handshake's
    /// codes away and make a relay's refusal answer `is_local() == true`. A
    /// failure this machine decided and a failure a peer sent would then be the
    /// same value.
    #[test]
    fn collapsing_several_addresses_keeps_a_peers_refusal_a_peers() {
        let addr: SocketAddr = "203.0.113.7:443".parse().unwrap();
        let refused = DialError::Transport(TransportError::Handshake(
            super::super::HandshakeFailure::transport(0x178, "peer refused the ALPN".into()),
        ));

        let named = e_at(addr, refused);
        assert_eq!(named.phase(), DialPhase::Handshake);
        assert!(!named.is_local(), "a peer answered this one");

        let DialError::Transport(TransportError::Handshake(failure)) = &named else {
            panic!("the typed handshake failure did not survive: {named}");
        };
        assert_eq!(failure.code, Some(0x178), "the code the refusal carried");
        assert_eq!(failure.tls_alert, Some(120), "0x178 is no_application_protocol");
        assert!(failure.reason.contains("203.0.113.7:443"), "{}", failure.reason);
        assert!(failure.reason.contains("peer refused the ALPN"), "{}", failure.reason);

        // The local phases keep their own variants through the same call.
        assert_eq!(
            e_at(addr, DialError::LocalSocket("no v6".into())).phase(),
            DialPhase::LocalSocket
        );
        assert_eq!(e_at(addr, DialError::TlsConfig("nope".into())).phase(), DialPhase::TlsConfig);
    }

    /// A timeout is a real outcome with no code in it, and inventing one would
    /// be worse than reporting none.
    #[test]
    fn a_failure_with_no_code_reports_none() {
        let timed_out = handshake_failure(&quinn::ConnectionError::TimedOut);
        assert_eq!(timed_out.code, None);
        assert_eq!(timed_out.tls_alert, None);
        assert!(!timed_out.reason.is_empty(), "the prose is all this failure has");
    }
}
