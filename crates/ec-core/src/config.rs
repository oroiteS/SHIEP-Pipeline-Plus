use crate::error::{EcError, EcResult};

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub server: String,
    pub username: String,
    pub password: String,
    pub socks_bind: String,
    pub fallback_proxy: Option<String>,
}

impl AppConfig {
    pub fn new(
        server: String,
        username: String,
        password: String,
        socks_bind: String,
        fallback_proxy: Option<String>,
    ) -> EcResult<Self> {
        let server = server.trim().to_string();
        let username = username.trim().to_string();
        let socks_bind = socks_bind.trim().to_string();
        let fallback_proxy = fallback_proxy
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        let cfg = Self {
            server,
            username,
            password,
            socks_bind,
            fallback_proxy,
        };
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> EcResult<()> {
        if self.server.trim().is_empty() {
            return Err(EcError::InvalidConfig("server is required"));
        }
        if self.username.trim().is_empty() {
            return Err(EcError::InvalidConfig("username is required"));
        }
        if self.password.is_empty() {
            return Err(EcError::InvalidConfig("password is required"));
        }
        if self.socks_bind.trim().is_empty() {
            return Err(EcError::InvalidConfig("socks-bind is required"));
        }
        Ok(())
    }
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
        )
        .unwrap();
        assert_eq!(cfg.server, "vpn.example.com:443");
        assert_eq!(cfg.username, "alice");
        assert_eq!(cfg.socks_bind, "127.0.0.1:1080");
    }
}
