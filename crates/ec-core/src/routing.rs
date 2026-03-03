use crate::error::{EcError, EcResult};
use crate::route_table::{PortRange, RouteRule, RouteTable};
use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, SocketAddr};
use std::str::FromStr;
use std::sync::{Arc, Mutex, OnceLock};

static ROUTER: OnceLock<Mutex<Option<Arc<RouteMatcher>>>> = OnceLock::new();
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
        source: RouteSource,
    },
    Fallback {
        target: String,
        reason: String,
        reserved_proto1: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RouteSource {
    RuleIp,
    DnsMap,
    DnsServerCache,
    DnsServerQuery(SocketAddr),
}

impl RouteSource {
    pub fn label(self) -> &'static str {
        match self {
            RouteSource::RuleIp => "rule-ip",
            RouteSource::DnsMap => "dns-map",
            RouteSource::DnsServerCache => "dns-cache",
            RouteSource::DnsServerQuery(_) => "dns-server",
        }
    }

    pub fn describe(self) -> String {
        match self {
            RouteSource::DnsServerQuery(server) => format!("dns-server({server})"),
            _ => self.label().to_string(),
        }
    }
}

pub fn install_route_table(table: RouteTable) -> EcResult<RouteInstallSummary> {
    let matcher = RouteMatcher::from_table(table)?;
    let summary = RouteInstallSummary {
        rule_count: matcher.rules.len(),
        dns_server_count: matcher.dns_servers.len(),
        dns_record_count: matcher.dns_records,
    };
    let holder = ROUTER.get_or_init(|| Mutex::new(None));
    let mut guard = holder
        .lock()
        .map_err(|_| EcError::Runtime("route matcher mutex poisoned".to_string()))?;
    crate::dns_resolver::clear_cache();
    *guard = Some(Arc::new(matcher));
    Ok(summary)
}

pub fn plan_target(host: &str, port: u16) -> EcResult<RoutePlan> {
    let holder = ROUTER
        .get()
        .ok_or_else(|| EcError::Runtime(ROUTER_NOT_INITIALIZED.to_string()))?;
    let matcher = holder
        .lock()
        .map_err(|_| EcError::Runtime("route matcher mutex poisoned".to_string()))?;
    let Some(matcher) = matcher.as_ref().cloned() else {
        return Err(EcError::Runtime(ROUTER_NOT_INITIALIZED.to_string()));
    };
    Ok(matcher.plan(host, port))
}

#[derive(Debug, Clone)]
struct RouteMatcher {
    rules: Vec<CompiledRule>,
    proto1_rules: Vec<CompiledRule>,
    dns_map: HashMap<i32, HashMap<String, Vec<Ipv4Addr>>>,
    dns_servers: Vec<String>,
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

        let (rules, proto1_rules) = compile_rules(raw_rules);
        let dns_map = build_dns_map(raw_dns_records);
        let dns_servers = normalize_dns_servers(dns_servers);

        let dns_records = dns_map
            .values()
            .flat_map(HashMap::values)
            .map(Vec::len)
            .sum();
        Ok(Self {
            rules,
            proto1_rules,
            dns_map,
            dns_servers,
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
                        source: RouteSource::RuleIp,
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
                            source: RouteSource::DnsMap,
                        };
                    }
                    if self.dns_servers.is_empty() {
                        return RoutePlan::Fallback {
                            target: format!("{host}:{port}"),
                            reason: format!(
                                "hostname matched rc_id={} but dns map is missing and dnsserver is unavailable",
                                rule.rc_id
                            ),
                            reserved_proto1: false,
                        };
                    }

                    match crate::dns_resolver::resolve_first_ipv4(
                        rule.rc_id,
                        domain,
                        &self.dns_servers,
                    ) {
                        Ok(resolved) => {
                            let source = match resolved.source {
                                crate::dns_resolver::ResolveSource::Cache => {
                                    RouteSource::DnsServerCache
                                }
                                crate::dns_resolver::ResolveSource::Server(server) => {
                                    RouteSource::DnsServerQuery(server)
                                }
                            };
                            return RoutePlan::Remote {
                                dial: format!("{}:{port}", resolved.ip),
                                rc_id: rule.rc_id,
                                rc_name: rule.rc_name.clone(),
                                source,
                            };
                        }
                        Err(err) => {
                            return RoutePlan::Fallback {
                                target: format!("{host}:{port}"),
                                reason: format!(
                                    "hostname matched rc_id={} but dns map is missing and dnsserver lookup failed: {}",
                                    rule.rc_id,
                                    crate::error::concise_error(err)
                                ),
                                reserved_proto1: false,
                            };
                        }
                    }
                }
            }
        }

        for rule in &self.proto1_rules {
            if !port_matches(rule.port, port) {
                continue;
            }
            if !host_matches(&rule.matcher, &target) {
                continue;
            }
            return RoutePlan::Fallback {
                target: format!("{host}:{port}"),
                reason: format!(
                    "matched reserved proto=1 rule rc_id={} name={}; proto=1 is separated from normal routing and forced to fallback",
                    rule.rc_id, rule.rc_name
                ),
                reserved_proto1: true,
            };
        }

        RoutePlan::Fallback {
            target: format!("{host}:{port}"),
            reason: "no whitelist rule matched".to_string(),
            reserved_proto1: false,
        }
    }
}

fn normalize_dns_servers(servers: Vec<String>) -> Vec<String> {
    let mut out = Vec::with_capacity(servers.len());
    let mut seen = HashSet::<String>::with_capacity(servers.len());
    for raw in servers {
        let token = raw.trim();
        if token.is_empty() {
            continue;
        }
        let key = token.to_ascii_lowercase();
        if seen.insert(key) {
            out.push(token.to_string());
        }
    }
    out
}

fn compile_rules(raw_rules: Vec<RouteRule>) -> (Vec<CompiledRule>, Vec<CompiledRule>) {
    let mut rules = Vec::with_capacity(raw_rules.len());
    let mut proto1_rules = Vec::with_capacity(raw_rules.len());
    let mut seen_rules = HashSet::<RuleDedupKey>::with_capacity(raw_rules.len());
    let mut seen_proto1_rules = HashSet::<RuleDedupKey>::with_capacity(raw_rules.len());
    for rule in raw_rules {
        if rule.proto == 1 {
            if let Some(compiled) = compile_rule(rule) {
                let key = compiled.dedup_key();
                if seen_proto1_rules.insert(key) {
                    proto1_rules.push(compiled);
                }
            }
            continue;
        }
        if let Some(compiled) = compile_rule(rule) {
            let key = compiled.dedup_key();
            if seen_rules.insert(key) {
                rules.push(compiled);
            }
        }
    }
    (rules, proto1_rules)
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
    use super::{RouteMatcher, RoutePlan, RouteSource};
    use crate::route_table::{DnsRecord, PortRange, RouteRule, RouteTable};

    #[test]
    fn domain_hit_uses_dns_map_ip() {
        let table = RouteTable {
            rules: vec![RouteRule {
                rc_id: 205,
                proto: 0,
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
                assert_eq!(source, RouteSource::DnsMap);
            }
            _ => panic!("expected remote plan"),
        }
    }

    #[test]
    fn ip_range_hit_goes_remote() {
        let table = RouteTable {
            rules: vec![RouteRule {
                rc_id: 334,
                proto: 0,
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
                assert_eq!(source, RouteSource::RuleIp);
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
                proto: 0,
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
                    proto: 0,
                    name: "qikan".to_string(),
                    host: "qikan.chaoxing.com".to_string(),
                    port: PortRange { start: 80, end: 80 },
                },
                RouteRule {
                    rc_id: 115,
                    proto: 0,
                    name: "qikan".to_string(),
                    host: "qikan.chaoxing.com".to_string(),
                    port: PortRange { start: 80, end: 80 },
                },
                RouteRule {
                    rc_id: 115,
                    proto: 0,
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

    #[test]
    fn dns_servers_are_deduped_and_trimmed() {
        let table = RouteTable {
            rules: vec![],
            dns_servers: vec![
                " 210.35.88.5 ".to_string(),
                "114.114.114.114".to_string(),
                "210.35.88.5".to_string(),
            ],
            dns_records: vec![],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        assert_eq!(
            matcher.dns_servers,
            vec!["210.35.88.5".to_string(), "114.114.114.114".to_string()]
        );
    }

    #[test]
    fn domain_hit_without_dns_map_uses_dnsserver_fallback_reason() {
        let table = RouteTable {
            rules: vec![RouteRule {
                rc_id: 205,
                proto: 0,
                name: "ids".to_string(),
                host: "ids.shiep.edu.cn".to_string(),
                port: PortRange {
                    start: 1,
                    end: 65535,
                },
            }],
            dns_servers: vec!["bad-server".to_string()],
            dns_records: vec![],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        let plan = matcher.plan("ids.shiep.edu.cn", 443);
        match plan {
            RoutePlan::Fallback { reason, .. } => {
                assert!(reason.contains("dnsserver lookup failed"));
            }
            _ => panic!("expected fallback plan"),
        }
    }

    #[test]
    fn proto1_rules_are_excluded_from_matching() {
        let table = RouteTable {
            rules: vec![RouteRule {
                rc_id: -98,
                proto: 1,
                name: "__DNS_HIDE_RC1".to_string(),
                host: "210.35.88.5".to_string(),
                port: PortRange { start: 53, end: 53 },
            }],
            dns_servers: vec![],
            dns_records: vec![],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        let plan = matcher.plan("210.35.88.5", 53);
        match plan {
            RoutePlan::Fallback { reason, .. } => {
                assert!(reason.contains("matched reserved proto=1 rule"));
            }
            _ => panic!("expected fallback plan"),
        }
    }
}
