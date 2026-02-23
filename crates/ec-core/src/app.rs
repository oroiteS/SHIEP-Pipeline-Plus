use crate::config::AppConfig;
use crate::error::EcResult;

pub struct EasyConnectApp {
    config: AppConfig,
}

impl EasyConnectApp {
    pub fn new(config: AppConfig) -> Self {
        Self { config }
    }

    pub fn run(&self) -> EcResult<()> {
        crate::transport::validate_transport_preconditions()?;
        crate::netstack::validate_netstack_preconditions()?;

        let twf_id = crate::auth::login(&self.config)?;
        let agent_token = crate::token::fetch_agent_token(&self.config.server, &twf_id)?;
        let token = format!("{agent_token}{twf_id}");
        let assigned_ip = crate::protocol::query_assigned_ip(&self.config.server, &token)?;
        crate::protocol::start_tunnel_runtime(&self.config.server, &token, assigned_ip)?;
        crate::socks::serve(&self.config.socks_bind)
    }
}
