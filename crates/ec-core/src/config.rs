use crate::error::{EcError, EcResult};

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub server: String,
    pub username: String,
    pub password: String,
    pub socks_bind: String,
}

impl AppConfig {
    pub fn new(
        server: String,
        username: String,
        password: String,
        socks_bind: String,
    ) -> EcResult<Self> {
        let cfg = Self {
            server,
            username,
            password,
            socks_bind,
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
            ":1080".to_string(),
        );
        assert!(result.is_ok());
    }

    #[test]
    fn rejects_empty_server() {
        let result = AppConfig::new(
            "".to_string(),
            "alice".to_string(),
            "secret".to_string(),
            ":1080".to_string(),
        );
        assert!(result.is_err());
    }
}
