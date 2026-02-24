use clap::{CommandFactory, FromArgMatches, Parser};
use ec_core::{AppConfig, EasyConnectApp};
use std::path::Path;

#[derive(Debug, Parser)]
#[command(name = "shiep-pipeline")]
#[command(about = "Minimal CLI-only EasyConnect pipeline")]
struct CliArgs {
    #[arg(long, help_heading = "Required", help = "VPN server address")]
    server: String,

    #[arg(long, help_heading = "Required", help = "VPN username")]
    username: String,

    #[arg(long, help_heading = "Required", help = "VPN password")]
    password: String,

    #[arg(
        long,
        default_value = ":1080",
        help_heading = "Optional",
        help = "Local bind address"
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

    let config = match AppConfig::new(
        args.server,
        args.username,
        args.password,
        args.socks_bind,
        args.fallback_proxy,
    ) {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("config error: {err}");
            std::process::exit(2);
        }
    };

    let app = EasyConnectApp::new(config);

    if let Err(err) = app.run() {
        eprintln!("runtime error: {err}");
        std::process::exit(1);
    }
}

fn parse_args() -> CliArgs {
    let mut cmd = CliArgs::command();
    let bin = std::env::args()
        .next()
        .and_then(|argv0| {
            Path::new(&argv0)
                .file_name()
                .map(|v| v.to_string_lossy().into_owned())
        })
        .filter(|v| !v.is_empty())
        .unwrap_or_else(|| cmd.get_name().to_string());

    let usage =
        format!("{bin} [OPTIONS] --server <SERVER> --username <USERNAME> --password <PASSWORD>");
    cmd = cmd.override_usage(usage);

    let matches = cmd.get_matches();
    CliArgs::from_arg_matches(&matches).unwrap_or_else(|e| e.exit())
}
