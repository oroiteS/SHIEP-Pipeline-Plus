use crate::error::{EcError, EcResult};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct AppConfig {
    pub server: String,
    pub username: String,
    pub password: String,
    pub socks_bind: String,
    pub fallback_proxy: Option<String>,
    pub extra_ips: Vec<String>,
    pub details: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct RememberedConfig {
    server: String,
    username: String,
}

const REMEMBERED_FILE: &str = "remembered.json";

fn load_remembered() -> Option<RememberedConfig> {
    let content = std::fs::read_to_string(REMEMBERED_FILE).ok()?;
    match serde_json::from_str::<RememberedConfig>(&content) {
        Ok(cfg) => Some(cfg),
        Err(e) => {
            crate::output::warn(
                crate::output::Scope::Cli,
                format_args!(
                    "failed to parse {}, ignoring: {}",
                    REMEMBERED_FILE, e
                ),
            );
            None
        }
    }
}

fn save_remembered(cfg: &RememberedConfig) {
    match serde_json::to_string_pretty(cfg) {
        Ok(json) => {
            if let Err(e) = std::fs::write(REMEMBERED_FILE, &json) {
                crate::output::warn(
                    crate::output::Scope::Cli,
                    format_args!("failed to write {}: {}", REMEMBERED_FILE, e),
                );
            }
        }
        Err(e) => {
            crate::output::warn(
                crate::output::Scope::Cli,
                format_args!("failed to serialize remembered config: {}", e),
            );
        }
    }
}

impl AppConfig {
    pub fn resolve(
        server: Option<String>,
        username: Option<String>,
        password: String,
        socks_bind: String,
        fallback_proxy: Option<String>,
        extra_ips: Vec<String>,
        details: bool,
        remember: bool,
    ) -> EcResult<Self> {
        let (server, username) = if remember {
            let remembered = load_remembered();
            let server = server.or_else(|| remembered.as_ref().map(|r| r.server.clone()));
            let username = username.or_else(|| remembered.as_ref().map(|r| r.username.clone()));
            let resolved_server =
                server.ok_or(EcError::InvalidConfig("server is required"))?;
            let resolved_username =
                username.ok_or(EcError::InvalidConfig("username is required"))?;

            save_remembered(&RememberedConfig {
                server: resolved_server.clone(),
                username: resolved_username.clone(),
            });

            (resolved_server, resolved_username)
        } else {
            let server = server.ok_or(EcError::InvalidConfig("server is required"))?;
            let username = username.ok_or(EcError::InvalidConfig("username is required"))?;
            (server, username)
        };

        Self::new(
            server,
            username,
            password,
            socks_bind,
            fallback_proxy,
            extra_ips,
            details,
        )
    }

    pub fn new(
        server: String,
        username: String,
        password: String,
        socks_bind: String,
        fallback_proxy: Option<String>,
        extra_ips: Vec<String>,
        details: bool,
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
            details,
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
    use super::{AppConfig, RememberedConfig, REMEMBERED_FILE};

    #[test]
    fn remembered_config_roundtrip() {
        let cfg = RememberedConfig {
            server: "vpn.example.com:443".into(),
            username: "alice".into(),
        };
        let json = serde_json::to_string(&cfg).unwrap();
        let parsed: RememberedConfig = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed.server, "vpn.example.com:443");
        assert_eq!(parsed.username, "alice");
    }

    #[test]
    fn resolve_without_remember_requires_server() {
        let result = AppConfig::resolve(
            None,
            Some("alice".into()),
            "secret".into(),
            "127.0.0.1:1080".into(),
            None,
            vec![],
            false,
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn resolve_without_remember_requires_username() {
        let result = AppConfig::resolve(
            Some("vpn.example.com:443".into()),
            None,
            "secret".into(),
            "127.0.0.1:1080".into(),
            None,
            vec![],
            false,
            false,
        );
        assert!(result.is_err());
    }

    #[test]
    fn resolve_without_remember_accepts_explicit_args() {
        let result = AppConfig::resolve(
            Some("vpn.example.com:443".into()),
            Some("alice".into()),
            "secret".into(),
            "127.0.0.1:1080".into(),
            None,
            vec![],
            false,
            false,
        );
        assert!(result.is_ok());
        let cfg = result.unwrap();
        assert_eq!(cfg.server, "vpn.example.com:443");
        assert_eq!(cfg.username, "alice");
    }

    #[test]
    fn resolve_with_remember_explicit_args_saves_file() {
        let _ = std::fs::remove_file(REMEMBERED_FILE);
        let result = AppConfig::resolve(
            Some("vpn.example.com:443".into()),
            Some("alice".into()),
            "secret".into(),
            "127.0.0.1:1080".into(),
            None,
            vec![],
            false,
            true,
        );
        assert!(result.is_ok());
        let saved = std::fs::read_to_string(REMEMBERED_FILE).unwrap();
        let parsed: RememberedConfig = serde_json::from_str(&saved).unwrap();
        assert_eq!(parsed.server, "vpn.example.com:443");
        assert_eq!(parsed.username, "alice");
        let _ = std::fs::remove_file(REMEMBERED_FILE);
    }

    #[test]
    fn resolve_with_remember_reads_saved_file() {
        let _ = std::fs::remove_file(REMEMBERED_FILE);
        let saved = RememberedConfig {
            server: "saved.example.com".into(),
            username: "saved_user".into(),
        };
        std::fs::write(REMEMBERED_FILE, serde_json::to_string(&saved).unwrap()).unwrap();

        let result = AppConfig::resolve(
            None,
            None,
            "secret".into(),
            "127.0.0.1:1080".into(),
            None,
            vec![],
            false,
            true,
        );
        assert!(result.is_ok());
        let cfg = result.unwrap();
        assert_eq!(cfg.server, "saved.example.com");
        assert_eq!(cfg.username, "saved_user");
        let _ = std::fs::remove_file(REMEMBERED_FILE);
    }

    #[test]
    fn resolve_with_remember_args_override_saved() {
        let _ = std::fs::remove_file(REMEMBERED_FILE);
        let saved = RememberedConfig {
            server: "saved.example.com".into(),
            username: "saved_user".into(),
        };
        std::fs::write(REMEMBERED_FILE, serde_json::to_string(&saved).unwrap()).unwrap();

        let result = AppConfig::resolve(
            Some("override.example.com".into()),
            None,
            "secret".into(),
            "127.0.0.1:1080".into(),
            None,
            vec![],
            false,
            true,
        );
        assert!(result.is_ok());
        let cfg = result.unwrap();
        assert_eq!(cfg.server, "override.example.com");
        assert_eq!(cfg.username, "saved_user");
        let updated = std::fs::read_to_string(REMEMBERED_FILE).unwrap();
        let parsed: RememberedConfig = serde_json::from_str(&updated).unwrap();
        assert_eq!(parsed.server, "override.example.com");
        let _ = std::fs::remove_file(REMEMBERED_FILE);
    }

    #[test]
    fn accepts_valid_config() {
        let result = AppConfig::new(
            "vpn.example.com:443".to_string(),
            "alice".to_string(),
            "secret".to_string(),
            "127.0.0.1:1080".to_string(),
            None,
            vec![],
            false,
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
            false,
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
            false,
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
            false,
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
            false,
        )
        .unwrap();
        assert_eq!(cfg.extra_ips, vec!["10.50.2.206", "10.50.2.0/24"]);
    }
}
