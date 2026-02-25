use anstyle::{Ansi256Color, Color, Style};
use chrono::Local;

#[derive(Clone, Copy)]
pub enum Scope {
    Cli,
    App,
    Login,
    Agent,
    Socks,
    Protocol,
    Netstack,
}

#[derive(Clone, Copy)]
pub enum Level {
    Info,
    Success,
    Warn,
    Error,
}

impl Scope {
    fn label(self) -> &'static str {
        match self {
            Scope::Cli => "CLI",
            Scope::App => "APP",
            Scope::Login => "LOGIN",
            Scope::Agent => "AGENT",
            Scope::Socks => "SOCKS5",
            Scope::Protocol => "VPN",
            Scope::Netstack => "NETSTACK",
        }
    }

    fn style(self) -> Style {
        match self {
            // High-saturation bright mapping for quick visual separation.
            Scope::Cli => style_ansi256(117),
            Scope::App => style_ansi256(81),
            Scope::Login => style_ansi256(118),
            Scope::Agent => style_ansi256(222),
            Scope::Socks => style_ansi256(213),
            Scope::Protocol => style_ansi256(214),
            Scope::Netstack => style_ansi256(33),
        }
    }
}

pub fn info(scope: Scope, message: impl AsRef<str>) {
    log(Level::Info, scope, message.as_ref());
}

pub fn warn(scope: Scope, message: impl AsRef<str>) {
    log(Level::Warn, scope, message.as_ref());
}

pub fn error(scope: Scope, message: impl AsRef<str>) {
    log(Level::Error, scope, message.as_ref());
}

pub fn success(scope: Scope, message: impl AsRef<str>) {
    log(Level::Success, scope, message.as_ref());
}

pub fn value(value: impl AsRef<str>) -> String {
    let value_style = style_ansi256(183);
    format!("{value_style}{}{value_style:#}", value.as_ref())
}

pub fn weak(value: impl AsRef<str>) -> String {
    let weak_style = style_ansi256(95);
    format!("{weak_style}{}{weak_style:#}", value.as_ref())
}

pub fn route_label(label: &str) -> String {
    let style = match label {
        "remote" => style_ansi256(81),
        "fallback" => style_ansi256(215),
        "direct" => style_ansi256(150),
        _ => style_ansi256(250),
    };
    format!("{style}{label}{style:#}")
}

fn log(level: Level, scope: Scope, message: &str) {
    emit(level, scope, message);
}

fn emit(level: Level, scope: Scope, message: &str) {
    let (year, short_date, clock) = timestamp_parts();
    let year_style = style_ansi256(240);
    let short_date_style = style_ansi256(244);
    let clock_style = style_ansi256(247);
    let scope_style = scope.style();
    match level {
        Level::Info => {
            anstream::eprintln!(
                "{year_style}{year}{year_style:#}{short_date_style}{short_date}{short_date_style:#}{clock_style}{clock}{clock_style:#} {scope_style}[{}]{scope_style:#} {message}",
                scope.label()
            );
        }
        Level::Success => {
            let ok_style = style_ansi256(34);
            anstream::eprintln!(
                "{year_style}{year}{year_style:#}{short_date_style}{short_date}{short_date_style:#}{clock_style}{clock}{clock_style:#} {scope_style}[{}]{scope_style:#} {ok_style}✓ {message}{ok_style:#}",
                scope.label()
            );
        }
        Level::Warn => {
            let warn_style = style_ansi256(220);
            anstream::eprintln!(
                "{year_style}{year}{year_style:#}{short_date_style}{short_date}{short_date_style:#}{clock_style}{clock}{clock_style:#} {scope_style}[{}]{scope_style:#} {warn_style}WARN:{warn_style:#} {message}",
                scope.label(),
            );
        }
        Level::Error => {
            let err_style = style_ansi256(196);
            anstream::eprintln!(
                "{year_style}{year}{year_style:#}{short_date_style}{short_date}{short_date_style:#}{clock_style}{clock}{clock_style:#} {scope_style}[{}]{scope_style:#} {err_style}ERROR:{err_style:#} {message}",
                scope.label(),
            );
        }
    }
}

fn style_ansi256(code: u8) -> Style {
    Style::new().fg_color(Some(Color::Ansi256(Ansi256Color(code))))
}

fn timestamp_parts() -> (String, String, String) {
    let now = Local::now();
    (
        now.format("%Y/").to_string(),
        now.format("%m/%d").to_string(),
        now.format(" %H:%M:%S%.3f").to_string(),
    )
}
