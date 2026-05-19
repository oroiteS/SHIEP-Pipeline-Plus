use crate::config::AppConfig;
use crate::error::EcResult;
use crate::output::{self, Scope};
use std::net::Ipv4Addr;

pub struct EasyConnectApp {
    config: AppConfig,
}

impl EasyConnectApp {
    pub fn new(config: AppConfig) -> Self {
        Self { config }
    }

    pub fn run(&self) -> EcResult<()> {
        Self::validate_preconditions()?;
        let twf_id = self.login()?;
        self.try_install_route_table(&twf_id)?;
        let token = self.acquire_protocol_token(&twf_id)?;
        let assigned_ip = self.start_tunnel(&token)?;
        crate::netstack::start_runtime(assigned_ip)?;
        crate::socks::serve(
            &self.config.socks_bind,
            self.config.fallback_proxy.as_deref(),
        )
    }

    fn validate_preconditions() -> EcResult<()> {
        crate::transport::validate_transport_preconditions()?;
        crate::netstack::validate_netstack_preconditions()?;
        Ok(())
    }

    fn login(&self) -> EcResult<String> {
        let twf_id = crate::auth::login(&self.config)?;
        output::success(
            Scope::Login,
            format_args!("session id acquired: {}", output::value(twf_id.as_str())),
        );
        Ok(twf_id)
    }

    fn try_install_route_table(&self, twf_id: &str) -> EcResult<()> {
        match crate::route_table::fetch_route_table(&self.config.server, twf_id) {
            Ok(table) => {
                if self.config.details {
                    crate::routing::log_table_details(&table, &self.config.extra_ips);
                }
                let install =
                    crate::routing::install_route_table(table, &self.config.extra_ips)?;
                output::info(
                    Scope::App,
                    format_args!(
                        "route table loaded: {} rules, {} dns servers, {} dns records",
                        output::value(install.rule_count),
                        output::value(install.dns_server_count),
                        output::value(install.dns_record_count)
                    ),
                );
            }
            Err(err) => {
                output::warn(
                    Scope::App,
                    format_args!(
                        "route table unavailable: {}",
                        crate::error::concise_error(err)
                    ),
                );
                output::warn(
                    Scope::App,
                    "split routing is disabled; fallback will use tunnel",
                );
            }
        }
        Ok(())
    }

    fn acquire_protocol_token(&self, twf_id: &str) -> EcResult<String> {
        output::info(Scope::Agent, "fetching agent token...");
        let agent_token = crate::token::fetch_agent_token(&self.config.server, twf_id)?;
        output::success(Scope::Agent, "agent token acquired");
        Ok(format!("{agent_token}{twf_id}"))
    }

    fn start_tunnel(&self, token: &str) -> EcResult<[u8; 4]> {
        output::info(Scope::Protocol, "querying assigned IP...");
        let assigned_ip = crate::protocol::query_assigned_ip(&self.config.server, token)?;
        output::success(
            Scope::Protocol,
            format_args!(
                "assigned IP: {}",
                output::value(Ipv4Addr::from(assigned_ip))
            ),
        );
        crate::protocol::start_tunnel_runtime(&self.config.server, token, assigned_ip)?;
        output::success(Scope::Protocol, "tunnel established");
        Ok(assigned_ip)
    }
}
