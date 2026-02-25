use anstyle::{Ansi256Color, Color, Style};
use chrono::Local;

#[derive(Clone, Copy)]
pub enum Scope {
    Cli,
    App,
    Login,
    Socks,
    Protocol,
    Netstack,
}

#[derive(Clone, Copy)]
pub enum Level {
    Info,
    Warn,
    Error,
}

impl Scope {
    fn label(self) -> &'static str {
        match self {
            Scope::Cli => "CLI",
            Scope::App => "APP",
            Scope::Login => "LOGIN",
            Scope::Socks => "SOCKS",
            Scope::Protocol => "PROTOCOL",
            Scope::Netstack => "NETSTACK",
        }
    }

    fn style(self) -> Style {
        match self {
            // High-saturation bright mapping for quick visual separation.
            Scope::Cli => style_ansi256(117),
            Scope::App => style_ansi256(81),
            Scope::Login => style_ansi256(118),
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

fn log(level: Level, scope: Scope, message: &str) {
    emit(level, scope, message);
}

fn emit(level: Level, scope: Scope, message: &str) {
    let timestamp = timestamp();
    let scope_style = scope.style();
    match level {
        Level::Info => {
            anstream::eprintln!(
                "{timestamp} {scope_style}[{}]{scope_style:#} {message}",
                scope.label()
            );
        }
        Level::Warn => {
            let warn_style = style_ansi256(220);
            anstream::eprintln!(
                "{timestamp} {warn_style}[WARN]{warn_style:#}{scope_style}[{}]{scope_style:#} {message}",
                scope.label()
            );
        }
        Level::Error => {
            let err_style = style_ansi256(196);
            anstream::eprintln!(
                "{timestamp} {err_style}[ERROR]{err_style:#}{scope_style}[{}]{scope_style:#} {message}",
                scope.label()
            );
        }
    }
}

fn style_ansi256(code: u8) -> Style {
    Style::new().fg_color(Some(Color::Ansi256(Ansi256Color(code))))
}

fn timestamp() -> String {
    Local::now().format("%Y/%m/%d %H:%M:%S%.3f").to_string()
}
