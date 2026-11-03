//! Relay URLs reduced to `scheme://host[:port][path]` before they leave the
//! process: query, fragment and userinfo are dropped, since they can carry a
//! token; the path is kept, normalised, since relays scope auth and
//! namespaces by path.

const RELAY_SCHEMES: [&str; 3] = ["https", "http", "moqt"];
const MAX_RELAY_URL: usize = 2048;

/// The relay's endpoint: lowercase scheme and host, punycode, no port when
/// it is the scheme's default (`moqt` has none), then the path: escapes in
/// uppercase hex, an escaped unreserved character decoded, any other
/// character outside RFC 3986's path set escaped from its UTF-8 bytes (a `%`
/// that starts no escape is `%25`), dot segments removed, and the root (an
/// empty path or `/`) written as no path. `None` when `url` is not a relay
/// URL, its path holds a space, a control character or `\`, or the endpoint
/// is longer than 2048 bytes.
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
        "https" => Some("443"),
        "http" => Some("80"),
        _ => None,
    };
    if default_port == Some(port.as_str()) {
        port.clear();
    }
    let mut out = if port.is_empty() {
        format!("{scheme}://{hostname}")
    } else {
        format!("{scheme}://{hostname}:{port}")
    };
    let path = &rest[authority_len..];
    let path = &path[..path.find(['?', '#']).unwrap_or(path.len())];
    out.push_str(&normalise_path(path)?);
    (out.len() <= MAX_RELAY_URL).then_some(out)
}

/// The host of an endpoint [`relay_endpoint`] wrote: no scheme, port or path.
pub(crate) fn relay_host(endpoint: &str) -> &str {
    let rest = endpoint.split_once("://").map_or(endpoint, |(_, r)| r);
    let authority = &rest[..rest.find('/').unwrap_or(rest.len())];
    if authority.starts_with('[') {
        return &authority[..authority.find(']').map_or(authority.len(), |i| i + 1)];
    }
    &authority[..authority.rfind(':').unwrap_or(authority.len())]
}

fn is_unreserved(b: u8) -> bool {
    b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
}

fn is_path_char(b: u8) -> bool {
    is_unreserved(b)
        || matches!(
            b,
            b'!' | b'$'
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
        )
}

fn normalise_path(raw: &str) -> Option<String> {
    let b = raw.as_bytes();
    if b.iter().any(|&c| c <= b' ' || c == 0x7f || c == b'\\') {
        return None;
    }
    let hex = |c: u8| (c as char).to_digit(16);
    let mut escaped = String::with_capacity(raw.len());
    let mut i = 0;
    while i < b.len() {
        let c = b[i];
        if c == b'%' {
            match (b.get(i + 1).copied().and_then(hex), b.get(i + 2).copied().and_then(hex)) {
                (Some(h), Some(l)) => {
                    let v = (h * 16 + l) as u8;
                    if is_unreserved(v) {
                        escaped.push(v as char);
                    } else {
                        escaped.push_str(&format!("%{v:02X}"));
                    }
                    i += 3;
                }
                _ => {
                    escaped.push_str("%25");
                    i += 1;
                }
            }
        } else if is_path_char(c) {
            escaped.push(c as char);
            i += 1;
        } else {
            escaped.push_str(&format!("%{c:02X}"));
            i += 1;
        }
    }
    let path = remove_dot_segments(&escaped);
    Some(if path == "/" { String::new() } else { path })
}

/// RFC 3986 Section 5.2.4.
fn remove_dot_segments(path: &str) -> String {
    let mut input = path;
    let mut out = String::with_capacity(path.len());
    let pop = |out: &mut String| out.truncate(out.rfind('/').unwrap_or(0));
    while !input.is_empty() {
        if let Some(r) = input.strip_prefix("../") {
            input = r;
        } else if let Some(r) = input.strip_prefix("./") {
            input = r;
        } else if input.starts_with("/./") {
            input = &input[2..];
        } else if input == "/." {
            input = "/";
        } else if input.starts_with("/../") {
            input = &input[3..];
            pop(&mut out);
        } else if input == "/.." {
            input = "/";
            pop(&mut out);
        } else if input == "." || input == ".." {
            input = "";
        } else {
            let from = usize::from(input.starts_with('/'));
            let end = input[from..].find('/').map_or(input.len(), |i| i + from);
            out.push_str(&input[..end]);
            input = &input[end..];
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::{relay_endpoint, relay_host};

    /// The endpoint's origin: scheme, host and port.
    fn o(s: &str) -> Option<String> {
        relay_endpoint(s).map(|e| {
            let start = e.find("://").map_or(0, |i| i + 3);
            let end = e[start..].find('/').map_or(e.len(), |i| i + start);
            e[..end].to_string()
        })
    }

    /// The same table as monitor-browser's relay tests.
    const ENDPOINTS: &[(&str, Option<&str>)] = &[
        ("https://relay.example", Some("https://relay.example")),
        ("https://relay.example/", Some("https://relay.example")),
        ("HTTPS://Relay.Example:443/", Some("https://relay.example")),
        ("moqt://relay.example:4443", Some("moqt://relay.example:4443")),
        ("moqt://relay.example/", Some("moqt://relay.example")),
        ("https://B\u{fc}cher.Example/moq", Some("https://xn--bcher-kva.example/moq")),
        ("moqt://B\u{fc}cher.Example:4443/moq", Some("moqt://xn--bcher-kva.example:4443/moq")),
        ("https://relay.example/moq", Some("https://relay.example/moq")),
        ("https://relay.example/moq/", Some("https://relay.example/moq/")),
        ("https://relay.example/Moq/A", Some("https://relay.example/Moq/A")),
        ("https://user:pw@relay.example/moq?jwt=secret#f", Some("https://relay.example/moq")),
        ("https://relay.example?jwt=secret", Some("https://relay.example")),
        ("https://relay.example/a//b", Some("https://relay.example/a//b")),
        ("https://relay.example/%7euser/%41", Some("https://relay.example/~user/A")),
        ("https://relay.example/a%2fb%3f", Some("https://relay.example/a%2Fb%3F")),
        ("https://relay.example/100%", Some("https://relay.example/100%25")),
        ("https://relay.example/%zz", Some("https://relay.example/%25zz")),
        ("https://relay.example/b\u{fc}cher", Some("https://relay.example/b%C3%BCcher")),
        (
            "https://relay.example/a|b[c]^{d}\"e",
            Some("https://relay.example/a%7Cb%5Bc%5D%5E%7Bd%7D%22e"),
        ),
        (
            "https://relay.example/a;v=1/!$&'()*+,=:@",
            Some("https://relay.example/a;v=1/!$&'()*+,=:@"),
        ),
        ("https://relay.example/a/./b/../c", Some("https://relay.example/a/c")),
        ("https://relay.example/a/%2E%2e/b", Some("https://relay.example/b")),
        ("https://relay.example/..", Some("https://relay.example")),
        ("https://relay.example/a/..", Some("https://relay.example")),
        ("https://relay.example/a/b/..", Some("https://relay.example/a/")),
        ("https://relay.example/a b", None),
        ("https://relay.example/a\tb", None),
        ("https://relay.example/a\\b", None),
        ("wss://relay.example/moq", None),
    ];

    #[test]
    fn keeps_the_normalised_path() {
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
    fn hosts() {
        assert_eq!(relay_host("https://relay.example/moq"), "relay.example");
        assert_eq!(relay_host("moqt://relay.example:4443/a"), "relay.example");
        assert_eq!(relay_host("https://[::1]:8443/x"), "[::1]");
        assert_eq!(relay_host("https://127.0.0.1:4433"), "127.0.0.1");
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
            ("moqt://Relay.Example:443/ns", "moqt://relay.example:443"),
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
