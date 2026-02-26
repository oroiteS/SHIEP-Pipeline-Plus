# SHIEP-Pipeline

SHIEP-Pipeline is a **Rust CLI-only** EasyConnect implementation for SHIEP.
The project focuses on minimal scope, clear structure, and maintainability, with no GUI.

## Design Goal

- Minimal CLI-only
- Reproduce the core connection flow first
- Refactor and organize code without adding unrelated features

## Current Capabilities

- Username/password login (RSA-encrypted password flow)
- Session and agent token acquisition
- VPN tunnel setup with RX/TX runtime
- Local SOCKS5 listener (CONNECT only, no auth)
- Automatic route-table fetch and parse (`/por/rclist.csp`) for split-routing decisions
- Route table based target decision (whitelist hit -> remote)
- Configurable fallback routing (non-whitelist -> direct or upstream proxy via `--fallback`)
- Structured, colorized logging that balances operational detail and visual clarity
- Supported fallback proxy schemes:
- `socks5://`
- `socks5h://`
- `http://`
- Bare `host:port` (interpreted as `socks5h://`)

## Project Structure

- `crates/ec-cli`
- CLI entry and argument parsing
- `crates/ec-core`
- Core implementation: login, protocol, tunnel, netstack, route-table parsing, SOCKS forwarding
- `.github/workflows/build-release.yml`
- Builds and uploads multi-platform artifacts after a release is published

## Quick Start

### Option A: Download From Release

1. Go to the latest release page on GitHub.
2. Download the artifact for your platform:
   - Linux: `SHIEP-Pipeline-<tag>-linux-x64`
   - macOS (Apple Silicon): `SHIEP-Pipeline-<tag>-macos-arm64`
   - Windows: `SHIEP-Pipeline-<tag>-windows-x64.exe`
3. Run it with required arguments:

```bash
./SHIEP-Pipeline --server <VPN_SERVER> --username <USERNAME> --password <PASSWORD>
```

### Option B: Run From Source

1. Install Rust stable
2. Install OpenSSL development dependencies (your system may already have them)
3. Run with Cargo

```bash
cargo run -p ec-cli -- --server <VPN_SERVER> --username <USERNAME> --password <PASSWORD>
```

Default listener address: `127.0.0.1:1080`.

## CLI Arguments

- `--server` required, VPN server address
- `--username` required, username
- `--password` required, password
- `--socks-bind` optional, local bind address, default `127.0.0.1:1080`
- `--fallback` optional, fallback upstream proxy address

Example:

```bash
./SHIEP-Pipeline --server <VPN_SERVER> --username <USERNAME> --password <PASSWORD> --fallback socks5h://127.0.0.1:114514
```

## Routing and Fallback

- The app fetches and parses route rules from `/por/rclist.csp`.
- If a whitelist rule matches, traffic goes remote (preferring mapped DNS IP).
- If no whitelist rule matches, traffic goes fallback.
- With `--fallback`, traffic goes through the upstream proxy.
- Without `--fallback`, traffic goes direct.

## Release Artifacts

The workflow triggers on GitHub Release `published` and uploads:

- Linux: `SHIEP-Pipeline-<tag>-linux-x64`
- macOS (Apple Silicon): `SHIEP-Pipeline-<tag>-macos-arm64`
- Windows: `SHIEP-Pipeline-<tag>-windows-x64.exe`

## Disclaimer

This project is for learning and research in authorized environments only.
Please follow your institution and network usage policies.

## Acknowledgements

- [NJUConnect](https://github.com/lyc8503/NJUConnect)
- [EasierConnect](https://github.com/Yan233th/EasierConnect)
