use clap::Parser;
use ec_core::{AppConfig, EasyConnectApp};

#[derive(Debug, Parser)]
#[command(name = "shiep-pipeline")]
#[command(about = "Minimal CLI-only EasyConnect pipeline")]
struct CliArgs {
    #[arg(long)]
    server: String,

    #[arg(long)]
    username: String,

    #[arg(long)]
    password: String,

    #[arg(long, default_value = ":1080")]
    socks_bind: String,

    #[arg(long = "fallback")]
    fallback_proxy: Option<String>,
}

fn main() {
    let args = CliArgs::parse();

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
