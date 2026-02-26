use crate::error::{EcError, EcResult};
use crate::route_table::{PortRange, RouteRule, RouteTable};
use std::collections::{HashMap, HashSet};
use std::net::Ipv4Addr;
use std::str::FromStr;
use std::sync::{Mutex, OnceLock};

static ROUTER: OnceLock<Mutex<Option<RouteMatcher>>> = OnceLock::new();
const ROUTER_NOT_INITIALIZED: &str = "route matcher is not initialized";

#[derive(Debug, Clone)]
pub struct RouteInstallSummary {
    pub rule_count: usize,
    pub dns_server_count: usize,
    pub dns_record_count: usize,
}

#[derive(Debug, Clone)]
pub enum RoutePlan {
    Remote {
        dial: String,
        rc_id: i32,
        rc_name: String,
        source: &'static str,
    },
    Fallback {
        target: String,
        reason: String,
    },
}

pub fn install_route_table(table: RouteTable) -> EcResult<RouteInstallSummary> {
    let matcher = RouteMatcher::from_table(table)?;
    let summary = RouteInstallSummary {
        rule_count: matcher.rules.len(),
        dns_server_count: matcher.dns_servers,
        dns_record_count: matcher.dns_records,
    };
    let holder = ROUTER.get_or_init(|| Mutex::new(None));
    let mut guard = holder
        .lock()
        .map_err(|_| EcError::Runtime("route matcher mutex poisoned".to_string()))?;
    *guard = Some(matcher);
    Ok(summary)
}

pub fn plan_target(host: &str, port: u16) -> EcResult<RoutePlan> {
    let holder = ROUTER
        .get()
        .ok_or_else(|| EcError::Runtime(ROUTER_NOT_INITIALIZED.to_string()))?;
    let guard = holder
        .lock()
        .map_err(|_| EcError::Runtime("route matcher mutex poisoned".to_string()))?;
    let Some(matcher) = guard.as_ref() else {
        return Err(EcError::Runtime(ROUTER_NOT_INITIALIZED.to_string()));
    };
    Ok(matcher.plan(host, port))
}

#[derive(Debug, Clone)]
struct RouteMatcher {
    rules: Vec<CompiledRule>,
    dns_map: HashMap<i32, HashMap<String, Vec<Ipv4Addr>>>,
    dns_servers: usize,
    dns_records: usize,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    rc_id: i32,
    rc_name: String,
    matcher: HostMatcher,
    port: PortRange,
}

#[derive(Debug, Clone)]
enum HostMatcher {
    Domain(String),
    Ipv4(Ipv4Addr),
    Ipv4Range(u32, u32),
}

#[derive(Debug, Clone)]
enum TargetKind {
    Domain(String),
    Ipv4(Ipv4Addr),
}

impl RouteMatcher {
    fn from_table(table: RouteTable) -> EcResult<Self> {
        let RouteTable {
            rules: raw_rules,
            dns_servers,
            dns_records: raw_dns_records,
            ..
        } = table;

        let rules = compile_rules(raw_rules);
        let dns_map = build_dns_map(raw_dns_records);

        let dns_records = dns_map
            .values()
            .flat_map(HashMap::values)
            .map(Vec::len)
            .sum();
        Ok(Self {
            rules,
            dns_map,
            dns_servers: dns_servers.len(),
            dns_records,
        })
    }

    fn plan(&self, host: &str, port: u16) -> RoutePlan {
        let target = parse_target(host);
        for rule in &self.rules {
            if !port_matches(rule.port, port) {
                continue;
            }
            if !host_matches(&rule.matcher, &target) {
                continue;
            }

            match &target {
                TargetKind::Ipv4(ip) => {
                    return RoutePlan::Remote {
                        dial: format!("{ip}:{port}"),
                        rc_id: rule.rc_id,
                        rc_name: rule.rc_name.clone(),
                        source: "rule-ip",
                    };
                }
                TargetKind::Domain(domain) => {
                    if let Some(ipv4s) = self
                        .dns_map
                        .get(&rule.rc_id)
                        .and_then(|domains| domains.get(domain))
                        && let Some(ip) = ipv4s.first()
                    {
                        return RoutePlan::Remote {
                            dial: format!("{ip}:{port}"),
                            rc_id: rule.rc_id,
                            rc_name: rule.rc_name.clone(),
                            source: "dns-map",
                        };
                    }
                    return RoutePlan::Fallback {
                        target: format!("{host}:{port}"),
                        reason: format!(
                            "hostname matched rc_id={} but dns map is missing",
                            rule.rc_id
                        ),
                    };
                }
            }
        }

        RoutePlan::Fallback {
            target: format!("{host}:{port}"),
            reason: "no whitelist rule matched".to_string(),
        }
    }
}

fn compile_rules(raw_rules: Vec<RouteRule>) -> Vec<CompiledRule> {
    let mut rules = Vec::with_capacity(raw_rules.len());
    let mut seen_rules = HashSet::<RuleDedupKey>::with_capacity(raw_rules.len());
    for rule in raw_rules {
        if let Some(compiled) = compile_rule(rule) {
            let key = compiled.dedup_key();
            if seen_rules.insert(key) {
                rules.push(compiled);
            }
        }
    }
    rules
}

fn build_dns_map(
    raw_dns_records: Vec<crate::route_table::DnsRecord>,
) -> HashMap<i32, HashMap<String, Vec<Ipv4Addr>>> {
    let mut dns_map = HashMap::<i32, HashMap<String, Vec<Ipv4Addr>>>::new();
    let mut seen_dns = HashSet::<(i32, String, Ipv4Addr)>::with_capacity(raw_dns_records.len());
    for rec in raw_dns_records {
        let host = normalize_domain(&rec.host);
        if host.is_empty() {
            continue;
        }
        let Ok(ip) = Ipv4Addr::from_str(rec.ip.trim()) else {
            continue;
        };
        if !seen_dns.insert((rec.rc_id, host.clone(), ip)) {
            continue;
        }
        dns_map
            .entry(rec.rc_id)
            .or_default()
            .entry(host)
            .or_default()
            .push(ip);
    }
    dns_map
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RuleDedupKey {
    rc_id: i32,
    rc_name: String,
    matcher: MatcherDedupKey,
    port_start: u16,
    port_end: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum MatcherDedupKey {
    Domain(String),
    Ipv4(Ipv4Addr),
    Ipv4Range(u32, u32),
}

impl CompiledRule {
    fn dedup_key(&self) -> RuleDedupKey {
        let matcher = match &self.matcher {
            HostMatcher::Domain(host) => MatcherDedupKey::Domain(host.clone()),
            HostMatcher::Ipv4(ip) => MatcherDedupKey::Ipv4(*ip),
            HostMatcher::Ipv4Range(a, b) => MatcherDedupKey::Ipv4Range(*a, *b),
        };
        RuleDedupKey {
            rc_id: self.rc_id,
            rc_name: self.rc_name.clone(),
            matcher,
            port_start: self.port.start,
            port_end: self.port.end,
        }
    }
}

fn compile_rule(rule: RouteRule) -> Option<CompiledRule> {
    let matcher = if rule.host.contains('~') {
        let (start, end) = rule.host.split_once('~')?;
        let a = Ipv4Addr::from_str(start.trim()).ok()?;
        let b = Ipv4Addr::from_str(end.trim()).ok()?;
        let ai = u32::from(a);
        let bi = u32::from(b);
        if ai <= bi {
            HostMatcher::Ipv4Range(ai, bi)
        } else {
            HostMatcher::Ipv4Range(bi, ai)
        }
    } else if let Ok(ip) = Ipv4Addr::from_str(rule.host.trim()) {
        HostMatcher::Ipv4(ip)
    } else {
        let domain = normalize_domain(&rule.host);
        if domain.is_empty() {
            return None;
        }
        HostMatcher::Domain(domain)
    };

    Some(CompiledRule {
        rc_id: rule.rc_id,
        rc_name: rule.name,
        matcher,
        port: rule.port,
    })
}

fn parse_target(host: &str) -> TargetKind {
    if let Ok(ip) = Ipv4Addr::from_str(host.trim()) {
        TargetKind::Ipv4(ip)
    } else {
        TargetKind::Domain(normalize_domain(host))
    }
}

fn normalize_domain(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

fn port_matches(range: PortRange, port: u16) -> bool {
    range.start <= port && port <= range.end
}

fn host_matches(rule: &HostMatcher, target: &TargetKind) -> bool {
    match (rule, target) {
        (HostMatcher::Domain(a), TargetKind::Domain(b)) => a == b,
        (HostMatcher::Ipv4(a), TargetKind::Ipv4(b)) => a == b,
        (HostMatcher::Ipv4Range(a, b), TargetKind::Ipv4(ip)) => {
            let n = u32::from(*ip);
            *a <= n && n <= *b
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::{RouteMatcher, RoutePlan};
    use crate::route_table::{DnsRecord, PortRange, RouteRule, RouteTable};

    #[test]
    fn domain_hit_uses_dns_map_ip() {
        let table = RouteTable {
            rules: vec![RouteRule {
                rc_id: 205,
                name: "ids".to_string(),
                host: "ids.shiep.edu.cn".to_string(),
                port: PortRange {
                    start: 1,
                    end: 65535,
                },
            }],
            dns_servers: vec![],
            dns_records: vec![DnsRecord {
                rc_id: 205,
                host: "ids.shiep.edu.cn".to_string(),
                ip: "10.166.35.11".to_string(),
            }],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        let plan = matcher.plan("ids.shiep.edu.cn", 443);
        match plan {
            RoutePlan::Remote {
                dial,
                rc_id,
                source,
                ..
            } => {
                assert_eq!(dial, "10.166.35.11:443");
                assert_eq!(rc_id, 205);
                assert_eq!(source, "dns-map");
            }
            _ => panic!("expected remote plan"),
        }
    }

    #[test]
    fn ip_range_hit_goes_remote() {
        let table = RouteTable {
            rules: vec![RouteRule {
                rc_id: 334,
                name: "fee".to_string(),
                host: "10.50.2.1~10.50.2.254".to_string(),
                port: PortRange { start: 80, end: 80 },
            }],
            dns_servers: vec![],
            dns_records: vec![],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        let plan = matcher.plan("10.50.2.206", 80);
        match plan {
            RoutePlan::Remote { dial, source, .. } => {
                assert_eq!(dial, "10.50.2.206:80");
                assert_eq!(source, "rule-ip");
            }
            _ => panic!("expected remote plan"),
        }
    }

    #[test]
    fn miss_falls_back() {
        let table = RouteTable {
            rules: vec![],
            dns_servers: vec![],
            dns_records: vec![],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        let plan = matcher.plan("example.com", 443);
        match plan {
            RoutePlan::Fallback { .. } => {}
            _ => panic!("expected fallback plan"),
        }
    }

    #[test]
    fn dns_duplicates_are_deduped_and_keep_order() {
        let table = RouteTable {
            rules: vec![RouteRule {
                rc_id: 205,
                name: "ids".to_string(),
                host: "ids.shiep.edu.cn".to_string(),
                port: PortRange {
                    start: 1,
                    end: 65535,
                },
            }],
            dns_servers: vec![],
            dns_records: vec![
                DnsRecord {
                    rc_id: 205,
                    host: "ids.shiep.edu.cn".to_string(),
                    ip: "10.166.35.11".to_string(),
                },
                DnsRecord {
                    rc_id: 205,
                    host: "ids.shiep.edu.cn".to_string(),
                    ip: "10.166.35.11".to_string(),
                },
                DnsRecord {
                    rc_id: 205,
                    host: "ids.shiep.edu.cn".to_string(),
                    ip: "10.166.35.12".to_string(),
                },
            ],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        assert_eq!(matcher.dns_records, 2);
        let ips = matcher
            .dns_map
            .get(&205)
            .and_then(|domains| domains.get("ids.shiep.edu.cn"))
            .unwrap();
        assert_eq!(ips.len(), 2);
        assert_eq!(ips[0].to_string(), "10.166.35.11");
        assert_eq!(ips[1].to_string(), "10.166.35.12");
    }

    #[test]
    fn duplicate_rules_are_deduped() {
        let table = RouteTable {
            rules: vec![
                RouteRule {
                    rc_id: 115,
                    name: "qikan".to_string(),
                    host: "qikan.chaoxing.com".to_string(),
                    port: PortRange { start: 80, end: 80 },
                },
                RouteRule {
                    rc_id: 115,
                    name: "qikan".to_string(),
                    host: "qikan.chaoxing.com".to_string(),
                    port: PortRange { start: 80, end: 80 },
                },
                RouteRule {
                    rc_id: 115,
                    name: "qikan".to_string(),
                    host: "qikan.chaoxing.com".to_string(),
                    port: PortRange {
                        start: 443,
                        end: 443,
                    },
                },
            ],
            dns_servers: vec![],
            dns_records: vec![],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        assert_eq!(matcher.rules.len(), 2);
    }
}
