//! Relay URLs reduced to `scheme://host[:port][path]` before they leave the
//! process: query, fragment and userinfo are dropped, since they can carry a
//! token; the path is kept exactly as the connection sends it, since a track
//! name is unique only within a scope, by default the authority and path
//! (draft-23 Section 2.5).

const RELAY_SCHEMES: [&str; 3] = ["https", "http", "moqt"];
const MAX_RELAY_URL: usize = 2048;

/// The relay's endpoint: lowercase scheme and host, punycode, no port when
/// it is the scheme's default (`moqt`: "If the port is omitted in the URI, a
/// default port of 443 is used", draft-15 Section 3.1.2, draft-23 Section 6.1.2),
/// then the path exactly as sent. An `https` or `http` path is the URL
/// parser's, which is the WebTransport request's `:path` (an empty path is
/// `/`). A `moqt` path is the URL's own path-abempty, which the native QUIC
/// SETUP PATH option carries (draft-23 Section 9.1.2), so `moqt://h` and
/// `moqt://h/` are two paths. `None` when `url` is not a relay URL, a `moqt`
/// path is not path-abempty, or the endpoint is longer than 2048 bytes.
pub(crate) fn relay_endpoint(url: &str) -> Option<String> {
    if url.is_empty() || url.len() > MAX_RELAY_URL {
        return None;
    }
    let (scheme, rest) = url.split_once("://")?;
    let valid_scheme = scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '.' | '-'));
    if !valid_scheme {
        return None;
    }
    let scheme = scheme.to_ascii_lowercase();
    if !RELAY_SCHEMES.contains(&scheme.as_str()) {
        return None;
    }
    let authority_len = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..authority_len];
    let authority = &authority[authority.rfind('@').map_or(0, |i| i + 1)..];
    if authority.chars().any(|c| c.is_whitespace() || c == '\\' || c == '%') {
        return None;
    }

    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let close = inner.find(']')?;
        let rest = &inner[close + 1..];
        let port = match rest {
            "" => "",
            _ => rest.strip_prefix(':')?,
        };
        (&authority[..close + 2], port)
    } else {
        match authority.rfind(':') {
            Some(i) => (&authority[..i], &authority[i + 1..]),
            None => (authority, ""),
        }
    };
    if host.is_empty() || port.len() > 5 || !port.chars().all(|c| c.is_ascii_digit()) {
        return None;
    }
    let mut port = match port {
        "" => String::new(),
        p => {
            let n: u32 = p.parse().ok()?;
            if n > 65_535 {
                return None;
            }
            n.to_string()
        }
    };

    let hostname = url::Url::parse(&format!("https://{host}/")).ok()?.host_str()?.to_string();
    if hostname.is_empty() {
        return None;
    }
    let default_port = match scheme.as_str() {
        "https" | "moqt" => "443",
        _ => "80",
    };
    if port == default_port {
        port.clear();
    }
    let mut out = if port.is_empty() {
        format!("{scheme}://{hostname}")
    } else {
        format!("{scheme}://{hostname}:{port}")
    };
    if scheme == "moqt" {
        let path = &rest[authority_len..];
        let path = &path[..path.find(['?', '#']).unwrap_or(path.len())];
        if !is_path_abempty(path) {
            return None;
        }
        out.push_str(path);
    } else {
        out.push_str(url::Url::parse(url).ok()?.path());
    }
    (out.len() <= MAX_RELAY_URL).then_some(out)
}

/// RFC 3986 path-abempty: `/`-led segments of pchars and percent-escapes.
fn is_path_abempty(path: &str) -> bool {
    let b = path.as_bytes();
    if !b.is_empty() && b[0] != b'/' {
        return false;
    }
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'%' {
            let hex = |j: usize| b.get(j).is_some_and(u8::is_ascii_hexdigit);
            if !(hex(i + 1) && hex(i + 2)) {
                return false;
            }
            i += 3;
            continue;
        }
        let pchar = c.is_ascii_alphanumeric()
            || matches!(
                c,
                b'-' | b'.'
                    | b'_'
                    | b'~'
                    | b'!'
                    | b'$'
                    | b'&'
                    | b'\''
                    | b'('
                    | b')'
                    | b'*'
                    | b'+'
                    | b','
                    | b';'
                    | b'='
                    | b':'
                    | b'@'
                    | b'/'
            );
        if !pchar {
            return false;
        }
        i += 1;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::relay_endpoint;

    /// The endpoint's origin: scheme, host and port.
    fn o(s: &str) -> Option<String> {
        relay_endpoint(s).map(|e| {
            let start = e.find("://").map_or(0, |i| i + 3);
            let end = e[start..].find('/').map_or(e.len(), |i| i + start);
            e[..end].to_string()
        })
    }

    /// The same table as ingest's and monitor-browser's relay tests.
    const ENDPOINTS: &[(&str, Option<&str>)] = &[
        ("https://relay.example", Some("https://relay.example/")),
        ("https://relay.example/", Some("https://relay.example/")),
        ("HTTPS://Relay.Example:443/", Some("https://relay.example/")),
        ("https://relay.example?jwt=secret", Some("https://relay.example/")),
        ("moqt://relay.example", Some("moqt://relay.example")),
        ("moqt://relay.example/", Some("moqt://relay.example/")),
        ("moqt://relay.example:443/moq", Some("moqt://relay.example/moq")),
        ("moqt://relay.example:4443", Some("moqt://relay.example:4443")),
        ("https://B\u{fc}cher.Example/moq", Some("https://xn--bcher-kva.example/moq")),
        ("moqt://B\u{fc}cher.Example:4443/moq", Some("moqt://xn--bcher-kva.example:4443/moq")),
        ("https://relay.example/moq", Some("https://relay.example/moq")),
        ("https://relay.example/moq/", Some("https://relay.example/moq/")),
        ("https://relay.example/Moq/A", Some("https://relay.example/Moq/A")),
        ("https://user:pw@relay.example/moq?jwt=secret#f", Some("https://relay.example/moq")),
        ("https://relay.example/a//b", Some("https://relay.example/a//b")),
        ("https://relay.example/%7euser/%41", Some("https://relay.example/%7euser/%41")),
        ("https://relay.example/a%2fb", Some("https://relay.example/a%2fb")),
        ("https://relay.example/100%", Some("https://relay.example/100%")),
        ("https://relay.example/b\u{fc}cher", Some("https://relay.example/b%C3%BCcher")),
        ("https://relay.example/a|b", Some("https://relay.example/a|b")),
        ("https://relay.example/a b", Some("https://relay.example/a%20b")),
        ("https://relay.example/a\tb", Some("https://relay.example/ab")),
        ("https://relay.example/a/./b/../c", Some("https://relay.example/a/c")),
        ("moqt://relay.example/a/./b/../c", Some("moqt://relay.example/a/./b/../c")),
        ("moqt://relay.example/%7e?jwt=secret", Some("moqt://relay.example/%7e")),
        (
            "moqt://relay.example/a;v=1/!$&'()*+,=:@",
            Some("moqt://relay.example/a;v=1/!$&'()*+,=:@"),
        ),
        ("moqt://relay.example/a b", None),
        ("moqt://relay.example/a|b", None),
        ("moqt://relay.example/b\u{fc}cher", None),
        ("moqt://relay.example/100%", None),
        ("wss://relay.example/moq", None),
    ];

    #[test]
    fn keeps_the_path_exactly() {
        for &(url, want) in ENDPOINTS {
            assert_eq!(relay_endpoint(url).as_deref(), want, "{url}");
            if let Some(w) = want {
                assert_eq!(relay_endpoint(w).as_deref(), Some(w), "{w} is a fixed point");
            }
        }
        let long = format!("https://relay.example/{}", "\u{fc}".repeat(400));
        assert_eq!(relay_endpoint(&long), None);
    }

    #[test]
    fn tells_moqt_h_from_moqt_h_slash() {
        assert_ne!(relay_endpoint("moqt://h"), relay_endpoint("moqt://h/"));
        assert_ne!(relay_endpoint("https://h/moq"), relay_endpoint("https://h/moq/"));
    }

    #[test]
    fn lowercases_scheme_and_host() {
        assert_eq!(
            o("HTTPS://Relay.Example.COM/moq").as_deref(),
            Some("https://relay.example.com")
        );
    }

    #[test]
    fn drops_the_default_port_only() {
        for (url, want) in [
            ("https://relay.example:443/x", "https://relay.example"),
            ("https://relay.example", "https://relay.example"),
            ("http://relay.example:80", "http://relay.example"),
            ("https://relay.example:4443", "https://relay.example:4443"),
            ("https://relay.example:0443", "https://relay.example"),
            ("http://relay.example:443", "http://relay.example:443"),
            ("moqt://Relay.Example:443/ns", "moqt://relay.example"),
            ("moqt://relay.example:4443", "moqt://relay.example:4443"),
            ("moqt://relay.example", "moqt://relay.example"),
        ] {
            assert_eq!(o(url).as_deref(), Some(want), "{url}");
        }
    }

    #[test]
    fn drops_query_fragment_and_userinfo() {
        for url in [
            "https://user:pw@relay.example/moq?jwt=secret#f",
            "https://relay.example?jwt=secret",
            "https://a@b@relay.example/",
        ] {
            assert_eq!(o(url).as_deref(), Some("https://relay.example"), "{url}");
        }
    }

    #[test]
    fn normalises_ip_literals_and_international_names() {
        assert_eq!(o("https://[0:0::1]:8443/x").as_deref(), Some("https://[::1]:8443"));
        assert_eq!(o("https://127.0.0.1:4433").as_deref(), Some("https://127.0.0.1:4433"));
        assert_eq!(o("https://Bücher.example").as_deref(), Some("https://xn--bcher-kva.example"));
    }

    #[test]
    fn refuses_what_is_not_a_relay_url() {
        let long = format!("https://{}", "a".repeat(2100));
        for bad in [
            "",
            "relay.example",
            "//relay.example",
            "wss://relay.example",
            "ftp://relay.example",
            "https://",
            "https://:443",
            "https://relay.example:99999",
            "https://relay.example:x",
            "https://[::1",
            "https://[::1]x",
            "https://re lay.example",
            "https://relay%2eexample",
            long.as_str(),
        ] {
            assert_eq!(relay_endpoint(bad), None, "{bad}");
        }
    }
}
