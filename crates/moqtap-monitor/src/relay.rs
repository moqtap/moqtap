//! Relay URLs reduced to `scheme://host[:port]` before they leave the process:
//! the path, query, fragment and userinfo are dropped, since a path or query
//! can carry a token.

const RELAY_SCHEMES: [&str; 3] = ["https", "http", "moqt"];
const MAX_RELAY_URL: usize = 2048;

/// The relay's origin: lowercase scheme and host, punycode, and no port when
/// it is the scheme's default (`moqt` has none). `None` when `url` is not a
/// relay URL.
pub(crate) fn relay_origin(url: &str) -> Option<String> {
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
    let authority = &rest[..rest.find(['/', '?', '#']).unwrap_or(rest.len())];
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
    Some(if port.is_empty() {
        format!("{scheme}://{hostname}")
    } else {
        format!("{scheme}://{hostname}:{port}")
    })
}

#[cfg(test)]
mod tests {
    use super::relay_origin;

    fn o(s: &str) -> Option<String> {
        relay_origin(s)
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
    fn drops_path_query_fragment_and_userinfo() {
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
            assert_eq!(o(bad), None, "{bad}");
        }
    }
}
