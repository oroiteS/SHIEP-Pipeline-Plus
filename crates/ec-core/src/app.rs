use crate::config::AppConfig;
use crate::error::EcResult;
use crate::output::{self, Scope};

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
        output::success(
            Scope::Login,
            format!("session id acquired: {}", output::value(twf_id.as_str())),
        );
        match crate::route_table::fetch_route_table(&self.config.server, &twf_id) {
            Ok(table) => {
                let install = crate::routing::install_route_table(table)?;
                output::info(
                    Scope::App,
                    format!(
                        "route table loaded: {} rules, {} dns records",
                        output::value(install.rule_count.to_string()),
                        output::value(install.dns_record_count.to_string())
                    ),
                );
            }
            Err(err) => {
                output::warn(Scope::App, format!("route table unavailable: {err}"));
                output::warn(
                    Scope::App,
                    "split routing is disabled; fallback will use tunnel",
                );
            }
        }
        output::info(Scope::Agent, "fetching agent token...");
        let agent_token = crate::token::fetch_agent_token(&self.config.server, &twf_id)?;
        output::success(Scope::Agent, "agent token acquired");
        let token = format!("{agent_token}{twf_id}");
        output::info(Scope::Protocol, "querying assigned IP...");
        let assigned_ip = crate::protocol::query_assigned_ip(&self.config.server, &token)?;
        output::success(
            Scope::Protocol,
            format!("assigned IP: {}", output::value(format_ipv4(assigned_ip))),
        );
        crate::protocol::start_tunnel_runtime(&self.config.server, &token, assigned_ip)?;
        output::success(Scope::Protocol, "tunnel established");
        crate::netstack::start_runtime(assigned_ip)?;
        crate::socks::serve(
            &self.config.socks_bind,
            self.config.fallback_proxy.as_deref(),
        )
    }
}

fn format_ipv4(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}
