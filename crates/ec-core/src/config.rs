use crate::error::{EcError, EcResult};

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub server: String,
    pub username: String,
    pub password: String,
    pub socks_bind: String,
    pub fallback_proxy: Option<String>,
    pub extra_ips: Vec<String>,
}

impl AppConfig {
    pub fn new(
        server: String,
        username: String,
        password: String,
        socks_bind: String,
        fallback_proxy: Option<String>,
        extra_ips: Vec<String>,
    ) -> EcResult<Self> {
        let server = trim_owned(server);
        let username = trim_owned(username);
        let socks_bind = trim_owned(socks_bind);
        let fallback_proxy = normalize_optional_trimmed(fallback_proxy);
        let extra_ips = extra_ips
            .into_iter()
            .map(trim_owned)
            .filter(|v| !v.is_empty())
            .collect();
        let cfg = Self {
            server,
            username,
            password,
            socks_bind,
            fallback_proxy,
            extra_ips,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> EcResult<()> {
        require_non_empty_trimmed(self.server.as_str(), "server is required")?;
        require_non_empty_trimmed(self.username.as_str(), "username is required")?;
        if self.password.is_empty() {
            return Err(EcError::InvalidConfig("password is required"));
        }
        require_non_empty_trimmed(self.socks_bind.as_str(), "bind is required")?;
        Ok(())
    }
}

fn trim_owned(value: String) -> String {
    value.trim().to_string()
}

fn normalize_optional_trimmed(value: Option<String>) -> Option<String> {
    value.map(trim_owned).filter(|v| !v.is_empty())
}

fn require_non_empty_trimmed(value: &str, error: &'static str) -> EcResult<()> {
    if value.trim().is_empty() {
        return Err(EcError::InvalidConfig(error));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::AppConfig;

    #[test]
    fn accepts_valid_config() {
        let result = AppConfig::new(
            "vpn.example.com:443".to_string(),
            "alice".to_string(),
            "secret".to_string(),
            "127.0.0.1:1080".to_string(),
            None,
            vec![],
        );
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_empty_server() {
        let result = AppConfig::new(
            "".to_string(),
            "alice".to_string(),
            "secret".to_string(),
            "127.0.0.1:1080".to_string(),
            None,
            vec![],
        );
        assert!(result.is_err());
    }

    #[test]
    fn trims_empty_fallback_proxy_to_none() {
        let cfg = AppConfig::new(
            "vpn.example.com:443".to_string(),
            "alice".to_string(),
            "secret".to_string(),
            "127.0.0.1:1080".to_string(),
            Some("   ".to_string()),
            vec![],
        )
        .unwrap();
        assert!(cfg.fallback_proxy.is_none());
    }

    #[test]
    fn trims_server_username_and_bind() {
        let cfg = AppConfig::new(
            "  vpn.example.com:443  ".to_string(),
            "  alice  ".to_string(),
            "secret".to_string(),
            " 127.0.0.1:1080 ".to_string(),
            None,
            vec![],
        )
        .unwrap();
        assert_eq!(cfg.server, "vpn.example.com:443");
        assert_eq!(cfg.username, "alice");
        assert_eq!(cfg.socks_bind, "127.0.0.1:1080");
    }

    #[test]
    fn trims_and_filters_empty_extra_ips() {
        let cfg = AppConfig::new(
            "vpn.example.com:443".to_string(),
            "alice".to_string(),
            "secret".to_string(),
            "127.0.0.1:1080".to_string(),
            None,
            vec![
                " 10.50.2.206 ".to_string(),
                "   ".to_string(),
                "10.50.2.0/24".to_string(),
            ],
        )
        .unwrap();
        assert_eq!(cfg.extra_ips, vec!["10.50.2.206", "10.50.2.0/24"]);
    }
}
