# Upstream V2 Plus Migration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Merge upstream v2.0.0 into SHIEP-Pipeline-Plus while preserving `--extra`, `--details`, and `--remember`.

**Architecture:** Treat upstream v2.0.0 as the baseline and reapply Plus behavior at CLI/config/app/routing boundaries. Keep upstream protocol, tunnel fallback, debug diagnostics, and logging behavior authoritative.

**Tech Stack:** Rust 2024 workspace, Cargo, clap, serde/serde_json, std networking.

---

## File Structure

- Modify `crates/ec-cli/src/main.rs`: combine upstream debug-aware config builder with Plus CLI arguments.
- Modify `crates/ec-core/src/config.rs`: combine upstream validation/debug config with Plus remembered config and extra route options.
- Modify `crates/ec-core/src/app.rs`: pass Plus options into routing while preserving upstream tunnel fallback.
- Modify `crates/ec-core/src/routing.rs`: add extra IP matchers and route details output to upstream v2.0.0 routing.
- Modify `crates/ec-core/Cargo.toml`: keep `serde` and `serde_json`.
- Modify `.gitignore`: keep `remembered.json` ignored.
- Modify `README.md`: document v2.0.0 behavior plus Plus options.

### Task 1: Establish Failing Coverage For Plus Config

**Files:**
- Modify: `crates/ec-core/src/config.rs`

- [ ] **Step 1: Ensure config tests cover Plus behavior and upstream password wording**

Add or preserve tests named:

```rust
#[test]
fn password_error_points_to_supported_inputs() {
    let err = AppConfig::new(
        "vpn.example.com:443".to_string(),
        "alice".to_string(),
        "".to_string(),
        "127.0.0.1:1080".to_string(),
        None,
        vec![],
        false,
    )
    .unwrap_err()
    .to_string();

    assert!(err.contains("--password"));
    assert!(err.contains("SHIEP_PIPELINE_PASSWORD"));
}

#[test]
fn trims_and_filters_empty_extra_ips() {
    let cfg = AppConfig::new(
        "vpn.example.com:443".to_string(),
        "alice".to_string(),
        "secret".to_string(),
        "127.0.0.1:1080".to_string(),
        None,
        vec![
            " 10.50.2.206 ".to_string(),
            "   ".to_string(),
            "10.50.2.0/24".to_string(),
        ],
        false,
    )
    .unwrap();
    assert_eq!(cfg.extra_ips, vec!["10.50.2.206", "10.50.2.0/24"]);
}
```

- [ ] **Step 2: Run targeted config tests before implementation**

Run: `cargo test -p ec-core config`

Expected before final implementation: failures or compile errors show missing merged signatures/fields after upstream merge.

### Task 2: Merge Upstream And Resolve Core Config/CLI

**Files:**
- Modify: `crates/ec-cli/src/main.rs`
- Modify: `crates/ec-core/src/config.rs`
- Modify: `crates/ec-core/Cargo.toml`
- Modify: `Cargo.lock`
- Modify: `.gitignore`

- [ ] **Step 1: Merge upstream**

Run: `git merge upstream/main`

Expected: conflicts in CLI/config/routing/app/docs or related files.

- [ ] **Step 2: Resolve config and CLI**

`CliArgs` must have `server: Option<String>`, `username: Option<String>`, `password`, `socks_bind`, `fallback_proxy`, `extra`, `details`, `remember`, and debug-only `debug`.

Debug builds call `AppConfig::resolve_with_debug(...)`. Release builds call `AppConfig::resolve(...)`.

`AppConfig` must include:

```rust
pub extra_ips: Vec<String>,
pub details: bool,
#[cfg(debug_assertions)]
pub debug_enabled: bool,
```

`new` validates password with upstream wording and defaults debug to false. `new_with_debug` and `resolve_with_debug` exist only in debug builds.

- [ ] **Step 3: Run targeted config tests**

Run: `cargo test -p ec-core config`

Expected: all config tests pass.

### Task 3: Reapply Plus Routing On Upstream V2 Routing

**Files:**
- Modify: `crates/ec-core/src/routing.rs`
- Modify: `crates/ec-core/src/app.rs`

- [ ] **Step 1: Ensure routing tests cover Plus behavior and upstream tunnel fallback**

Add or preserve tests named:

```rust
#[test]
fn extra_ip_single_match() { /* verifies RouteSource::ExtraIp */ }

#[test]
fn extra_ip_range_match() { /* verifies RouteSource::ExtraIp */ }

#[test]
fn extra_ip_cidr_match() { /* verifies RouteSource::ExtraIp */ }

#[test]
fn extra_ip_no_match() { /* verifies fallback reason */ }

#[test]
fn tunnel_fallback_mode_routes_everything_remote() { /* verifies RouteSource::RouteTableUnavailable */ }
```

- [ ] **Step 2: Implement extra matchers on upstream routing**

Add `RouteSource::ExtraIp`, `RouteMatcher.extra_matchers`, `parse_extra_ip`, and `plan_extra_ip`.

`install_route_table` signature becomes:

```rust
pub fn install_route_table(
    table: RouteTable,
    extra_ips: &[String],
) -> EcResult<RouteInstallSummary>
```

`RouteMatcher::from_table` signature becomes:

```rust
fn from_table(table: RouteTable, extra_ips: &[String]) -> EcResult<Self>
```

Existing tests without extras pass `&[]`.

- [ ] **Step 3: Implement details output**

Add:

```rust
pub fn log_table_details(table: &RouteTable, extra_ips: &[String])
```

It writes `route-details.txt` and logs success/warning. `EasyConnectApp::try_install_route_table` calls it only when `self.config.details` is true and before installing the route table.

- [ ] **Step 4: Preserve upstream route table unavailable behavior**

On route table fetch error, `EasyConnectApp` still calls `crate::routing::install_tunnel_fallback()?`.

- [ ] **Step 5: Run targeted routing tests**

Run: `cargo test -p ec-core routing`

Expected: all routing tests pass.

### Task 4: Documentation And Full Verification

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update README**

Document upstream v2.0.0 quick start and Plus options:

```text
--extra <IP>      extra IPv4/CIDR/range tunnel route, repeatable
--details         write route-details.txt after fetching the route table
--remember        remember server and username in remembered.json
```

Mention that `remembered.json` does not store the password.

- [ ] **Step 2: Run full tests**

Run: `cargo test`

Expected: all tests pass.

- [ ] **Step 3: Run build**

Run: `cargo build`

Expected: build succeeds.

- [ ] **Step 4: Inspect final status**

Run: `git status --short --branch`

Expected: merge is complete with only intended modified files staged or unstaged.

## Self-Review

- Spec coverage: all confirmed Plus features are covered; upstream v2.0.0 behavior is preserved explicitly.
- Placeholder scan: no unresolved implementation placeholders remain in executable instructions.
- Type consistency: `AppConfig::new`, `resolve`, and routing signatures consistently include `extra_ips` and `details`.

