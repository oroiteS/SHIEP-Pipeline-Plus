use clap::{CommandFactory, FromArgMatches, Parser};
use ec_core::output::{self, Scope};
use ec_core::{AppConfig, EasyConnectApp};
use std::path::Path;

#[derive(Debug, Parser)]
#[command(name = "SHIEP-Pipeline")]
#[command(about = "Minimal CLI-only EasyConnect pipeline")]
struct CliArgs {
    #[arg(long, help_heading = "Required", help = "VPN server address")]
    server: String,

    #[arg(long, help_heading = "Required", help = "VPN username")]
    username: String,

    #[arg(long, help_heading = "Required", help = "VPN password")]
    password: String,

    #[arg(
        long = "bind",
        value_name = "BIND",
        default_value = "127.0.0.1:1080",
        help_heading = "Optional",
        help = "Local listener bind address"
    )]
    socks_bind: String,

    #[arg(
        long = "fallback",
        help_heading = "Optional",
        help = "Fallback upstream proxy address"
    )]
    fallback_proxy: Option<String>,
}

fn main() {
    let args = parse_args();
    output::info(
        Scope::App,
        format_args!(
            "{} {}",
            output::value("SHIEP-Pipeline"),
            output::value(app_version())
        ),
    );

    let config = match AppConfig::new(
        args.server,
        args.username,
        args.password,
        args.socks_bind,
        args.fallback_proxy,
    ) {
        Ok(cfg) => cfg,
        Err(err) => {
            output::error(
                Scope::Cli,
                format_args!("config error: {}", ec_core::error::concise_error(err)),
            );
            std::process::exit(2);
        }
    };

    let app = EasyConnectApp::new(config);

    if let Err(err) = app.run() {
        output::error(Scope::Cli, ec_core::error::concise_error(err));
        std::process::exit(1);
    }
}

fn app_version() -> &'static str {
    option_env!("SHIEP_PIPELINE_VERSION").unwrap_or(env!("CARGO_PKG_VERSION"))
}

fn parse_args() -> CliArgs {
    let mut cmd = CliArgs::command();
    let bin = current_bin_name().unwrap_or_else(|| cmd.get_name().to_string());

    let usage =
        format!("{bin} [OPTIONS] --server <SERVER> --username <USERNAME> --password <PASSWORD>");
    cmd = cmd.version(app_version()).override_usage(usage);

    let matches = cmd.get_matches();
    CliArgs::from_arg_matches(&matches).unwrap_or_else(|e| e.exit())
}

fn current_bin_name() -> Option<String> {
    std::env::args()
        .next()
        .and_then(|argv0| {
            Path::new(&argv0)
                .file_name()
                .map(|v| v.to_string_lossy().into_owned())
        })
        .filter(|v| !v.is_empty())
}
