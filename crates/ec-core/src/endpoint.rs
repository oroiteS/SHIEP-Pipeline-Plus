use crate::error::{EcError, EcResult};

pub(crate) fn parse_server(server: &str) -> EcResult<(String, String)> {
    let trimmed = server.trim();
    if trimmed.is_empty() {
        return Err(EcError::InvalidConfig("server is required"));
    }

    let no_scheme = trimmed
        .strip_prefix("https://")
        .or_else(|| trimmed.strip_prefix("http://"))
        .unwrap_or(trimmed);
    let authority_raw = no_scheme
        .split('/')
        .next()
        .ok_or_else(|| EcError::Runtime("invalid server address".to_string()))?;
    if authority_raw.is_empty() {
        return Err(EcError::Runtime("invalid server authority".to_string()));
    }

    let authority = if has_explicit_port(authority_raw) {
        authority_raw.to_string()
    } else {
        format!("{authority_raw}:443")
    };
    let host = extract_host(&authority)?;
    Ok((authority, host))
}

fn has_explicit_port(authority: &str) -> bool {
    if authority.starts_with('[') {
        authority.contains("]:")
    } else {
        authority.rsplit_once(':').is_some()
    }
}

fn extract_host(authority: &str) -> EcResult<String> {
    if authority.starts_with('[') {
        let end = authority
            .find(']')
            .ok_or_else(|| EcError::Runtime("invalid ipv6 authority format".to_string()))?;
        return Ok(authority[1..end].to_string());
    }

    if let Some((host, _)) = authority.rsplit_once(':') {
        if host.is_empty() {
            return Err(EcError::Runtime(
                "invalid host in server authority".to_string(),
            ));
        }
        return Ok(host.to_string());
    }

    Ok(authority.to_string())
}

#[cfg(test)]
mod tests {
    use super::{extract_host, has_explicit_port, parse_server};

    #[test]
    fn parse_server_defaults_to_443() {
        let (authority, host) = parse_server("vpn.example.com").unwrap();
        assert_eq!(authority, "vpn.example.com:443");
        assert_eq!(host, "vpn.example.com");
    }

    #[test]
    fn parse_server_keeps_explicit_port() {
        let (authority, host) = parse_server("https://vpn.example.com:8443").unwrap();
        assert_eq!(authority, "vpn.example.com:8443");
        assert_eq!(host, "vpn.example.com");
    }

    #[test]
    fn parse_server_ipv6_with_port() {
        let (authority, host) = parse_server("https://[2001:db8::1]:443").unwrap();
        assert_eq!(authority, "[2001:db8::1]:443");
        assert_eq!(host, "2001:db8::1");
    }

    #[test]
    fn host_and_port_helpers() {
        assert!(has_explicit_port("vpn.example.com:443"));
        assert!(!has_explicit_port("vpn.example.com"));
        assert_eq!(
            extract_host("vpn.example.com:443").unwrap(),
            "vpn.example.com"
        );
    }
}
