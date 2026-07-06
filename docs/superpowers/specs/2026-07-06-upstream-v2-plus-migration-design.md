# Upstream v2 Plus Migration Design

## Goal

Synchronize SHIEP-Pipeline-Plus with upstream SHIEP-Pipeline v2.0.0 while preserving Plus user-facing behavior.

## Scope

The migration targets upstream `upstream/main` at `49bf483` (`v2.0.0`) and keeps these Plus features:

- `--extra <IP>`: manually route extra IPv4 single addresses, ranges, and CIDR blocks through the VPN tunnel.
- `--details`: write route table details to `route-details.txt` after a route table is fetched.
- `--remember`: save server and username in `remembered.json`; never save the password.

The migration also preserves upstream v2.0.0 behavior:

- Debug builds expose `--debug`; release builds do not.
- Missing route tables degrade to tunnel mode with `RouteSource::RouteTableUnavailable`.
- Password validation mentions both `--password` and `SHIEP_PIPELINE_PASSWORD`.
- Upstream protocol, logging, SOCKS, netstack, and route matching changes remain authoritative.

## Architecture

Use upstream v2.0.0 as the behavioral baseline. Reintegrate Plus behavior at the narrow public boundaries: CLI argument parsing, `AppConfig`, route table installation, and route matching.

`AppConfig` owns normalized configuration values: credentials, listener bind address, fallback proxy, Plus route flags, and debug state in debug builds. `EasyConnectApp` passes Plus route settings into routing only after successful route table fetches. Routing remains responsible for compiling matchers and selecting route plans.

## Components

- `crates/ec-cli/src/main.rs`: parse upstream CLI options plus `--extra`, `--details`, and `--remember`; build configs through release/debug aware helpers.
- `crates/ec-core/src/config.rs`: add optional server/username resolution for `--remember`, normalized `extra_ips`, `details`, and debug support.
- `crates/ec-core/src/app.rs`: call `log_table_details` when requested and install the route table with `extra_ips`; keep upstream tunnel fallback on route table fetch failure.
- `crates/ec-core/src/routing.rs`: add `RouteSource::ExtraIp`, extra IPv4 matchers, route details output, and tests without weakening upstream matching semantics.
- `crates/ec-core/Cargo.toml` and `Cargo.lock`: keep `serde` and `serde_json` for `remembered.json`.
- `README.md` and `.gitignore`: document Plus behavior and keep `remembered.json` ignored.

## Behavior Details

`--extra` accepts:

- Single IPv4: `10.50.2.206`
- IPv4 range: `10.50.2.1~10.50.2.254`
- CIDR: `10.50.2.0/24`

Extra entries match only IPv4 targets. They do not invent domain routing by themselves. If the target is already an IP and matches an extra matcher, the route plan goes remote with `rc_id = 0`, `rc_name = "--extra"`, and `RouteSource::ExtraIp`.

`--details` writes a plain text route summary to `route-details.txt`. If writing fails, the app logs a warning and continues.

`--remember` makes `--server` and `--username` optional only when saved values exist or explicit values are supplied. Password still comes from `--password` or `SHIEP_PIPELINE_PASSWORD` and is still required.

## Testing

Run targeted tests for `config` and `routing` after each behavior change, then full `cargo test`, then `cargo build`. Tests must cover:

- `--remember` read/write/override behavior.
- New password validation wording remains intact.
- Empty `extra_ips` values are trimmed and dropped.
- Single, range, and CIDR `--extra` matchers route remote.
- Nonmatching extra targets fall back.
- Tunnel fallback mode remains remote for all targets.

