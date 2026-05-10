use crate::error::{EcError, EcResult};
use crate::route_table::{PortRange, RouteRule, RouteTable};
use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
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
    DnsData,
    DnsServerCache,
    DnsServerQuery(SocketAddr),
    CnameDnsMap,
    CnameDnsServerCache,
    CnameDnsServerQuery(SocketAddr),
}

impl RouteSource {
    pub fn label(self) -> &'static str {
        match self {
            RouteSource::RuleIp => "rule-ip",
            RouteSource::DnsMap => "dns-map",
            RouteSource::DnsData => "dns-data",
            RouteSource::DnsServerCache => "dns-cache",
            RouteSource::DnsServerQuery(_) => "dns-server",
            RouteSource::CnameDnsMap => "cname-dns-map",
            RouteSource::CnameDnsServerCache => "cname-dns-cache",
            RouteSource::CnameDnsServerQuery(_) => "cname-dns-server",
        }
    }

    pub fn describe(self) -> String {
        match self {
            RouteSource::DnsServerQuery(server) => format!("dns-server({server})"),
            RouteSource::CnameDnsServerQuery(server) => format!("cname-dns-server({server})"),
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
    rule_index: RuleIndex,
    proto1_rules: Vec<CompiledRule>,
    proto1_index: RuleIndex,
    dns_map: HashMap<i32, HashMap<String, Vec<Ipv4Addr>>>,
    dns_exact: HashMap<String, Vec<DnsDataRecord>>,
    dns_servers: Vec<SocketAddr>,
    dns_records: usize,
}

#[derive(Debug, Clone)]
struct CompiledRule {
    rc_id: i32,
    rc_name: String,
    matcher: HostMatcher,
    port: PortRange,
}

#[derive(Debug, Clone, Copy)]
struct DnsDataRecord {
    rc_id: i32,
    ip: Ipv4Addr,
}

#[derive(Debug, Clone, Default)]
struct RuleIndex {
    domain: HashMap<String, Vec<usize>>,
    ipv4: HashMap<Ipv4Addr, Vec<usize>>,
    range_buckets: Vec<Vec<usize>>,
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
        let rule_index = RuleIndex::build(&rules);
        let proto1_index = RuleIndex::build(&proto1_rules);
        let dns_indexes = build_dns_indexes(raw_dns_records);
        let dns_servers = normalize_dns_servers(dns_servers);

        Ok(Self {
            rules,
            rule_index,
            proto1_rules,
            proto1_index,
            dns_map: dns_indexes.scoped,
            dns_exact: dns_indexes.exact,
            dns_servers,
            dns_records: dns_indexes.record_count,
        })
    }

    fn plan(&self, host: &str, port: u16) -> RoutePlan {
        let target = parse_target(host);
        if let Some(rule) = self.rule_index.find_first_match(&self.rules, &target, port) {
            return self.plan_remote_with_rule(rule, host, port, &target);
        }

        if let Some(rule) = self
            .proto1_index
            .find_first_match(&self.proto1_rules, &target, port)
        {
            return RoutePlan::Fallback {
                target: format!("{host}:{port}"),
                reason: format!(
                    "matched reserved proto=1 rule rc_id={} name={}; proto=1 is separated from normal routing and forced to fallback",
                    rule.rc_id, rule.rc_name
                ),
                reserved_proto1: true,
            };
        }

        if let TargetKind::Domain(domain) = &target
            && let Some(records) = self.dns_exact.get(domain)
            && let Some(record) = records.first()
        {
            return RoutePlan::Remote {
                dial: format!("{}:{port}", record.ip),
                rc_id: record.rc_id,
                rc_name: "dns.data".to_string(),
                source: RouteSource::DnsData,
            };
        }

        if let TargetKind::Domain(domain) = &target
            && let Some(plan) = self.plan_cname_aliases(host, port, domain)
        {
            return plan;
        }

        RoutePlan::Fallback {
            target: format!("{host}:{port}"),
            reason: "no whitelist rule matched".to_string(),
            reserved_proto1: false,
        }
    }

    fn plan_remote_with_rule(
        &self,
        rule: &CompiledRule,
        host: &str,
        port: u16,
        target: &TargetKind,
    ) -> RoutePlan {
        match target {
            TargetKind::Ipv4(ip) => RoutePlan::Remote {
                dial: format!("{ip}:{port}"),
                rc_id: rule.rc_id,
                rc_name: rule.rc_name.clone(),
                source: RouteSource::RuleIp,
            },
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

                match crate::dns_resolver::resolve_first_ipv4(rule.rc_id, domain, &self.dns_servers)
                {
                    Ok(resolved) => {
                        let source = match resolved.source {
                            crate::dns_resolver::ResolveSource::Cache => {
                                RouteSource::DnsServerCache
                            }
                            crate::dns_resolver::ResolveSource::Server(server) => {
                                RouteSource::DnsServerQuery(server)
                            }
                        };
                        RoutePlan::Remote {
                            dial: format!("{}:{port}", resolved.ip),
                            rc_id: rule.rc_id,
                            rc_name: rule.rc_name.clone(),
                            source,
                        }
                    }
                    Err(err) => RoutePlan::Fallback {
                        target: format!("{host}:{port}"),
                        reason: format!(
                            "hostname matched rc_id={} but dns map is missing and dnsserver lookup failed: {}",
                            rule.rc_id,
                            crate::error::concise_error(err)
                        ),
                        reserved_proto1: false,
                    },
                }
            }
        }
    }

    fn plan_cname_aliases(&self, host: &str, port: u16, domain: &str) -> Option<RoutePlan> {
        if self.dns_servers.is_empty() {
            return None;
        }
        let resolved = crate::dns_resolver::resolve_cname_chain(domain, &self.dns_servers).ok()?;
        self.plan_from_cname_aliases(host, port, &resolved.aliases)
    }

    fn plan_from_cname_aliases(
        &self,
        host: &str,
        port: u16,
        aliases: &[String],
    ) -> Option<RoutePlan> {
        for alias in aliases {
            let alias = normalize_domain(alias);
            if alias.is_empty() || Ipv4Addr::from_str(&alias).is_ok() {
                continue;
            }
            let target = TargetKind::Domain(alias);
            if let Some(rule) = self.rule_index.find_first_match(&self.rules, &target, port) {
                return Some(self.plan_remote_with_cname_rule(rule, host, port, &target));
            }
            if let Some(rule) =
                self.proto1_index
                    .find_first_match(&self.proto1_rules, &target, port)
            {
                return Some(RoutePlan::Fallback {
                    target: format!("{host}:{port}"),
                    reason: format!(
                        "cname matched reserved proto=1 rule rc_id={} name={}; proto=1 is separated from normal routing and forced to fallback",
                        rule.rc_id, rule.rc_name
                    ),
                    reserved_proto1: true,
                });
            }
        }
        None
    }

    fn plan_remote_with_cname_rule(
        &self,
        rule: &CompiledRule,
        host: &str,
        port: u16,
        target: &TargetKind,
    ) -> RoutePlan {
        match self.plan_remote_with_rule(rule, host, port, target) {
            RoutePlan::Remote {
                dial,
                rc_id,
                rc_name,
                source,
            } => RoutePlan::Remote {
                dial,
                rc_id,
                rc_name,
                source: cname_route_source(source),
            },
            other => other,
        }
    }
}

fn cname_route_source(source: RouteSource) -> RouteSource {
    match source {
        RouteSource::DnsMap => RouteSource::CnameDnsMap,
        RouteSource::DnsServerCache => RouteSource::CnameDnsServerCache,
        RouteSource::DnsServerQuery(server) => RouteSource::CnameDnsServerQuery(server),
        other => other,
    }
}

impl RuleIndex {
    fn build(rules: &[CompiledRule]) -> Self {
        let mut index = Self {
            domain: HashMap::new(),
            ipv4: HashMap::new(),
            range_buckets: vec![Vec::new(); 256],
        };
        for (idx, rule) in rules.iter().enumerate() {
            match &rule.matcher {
                HostMatcher::Domain(domain) => {
                    index.domain.entry(domain.clone()).or_default().push(idx);
                }
                HostMatcher::Ipv4(ip) => {
                    index.ipv4.entry(*ip).or_default().push(idx);
                }
                HostMatcher::Ipv4Range(start, end) => {
                    let start_bucket = ((*start >> 24) & 0xff) as usize;
                    let end_bucket = ((*end >> 24) & 0xff) as usize;
                    for bucket in start_bucket..=end_bucket {
                        index.range_buckets[bucket].push(idx);
                    }
                }
            }
        }
        index
    }

    fn find_first_match<'a>(
        &self,
        rules: &'a [CompiledRule],
        target: &TargetKind,
        port: u16,
    ) -> Option<&'a CompiledRule> {
        match target {
            TargetKind::Domain(domain) => self
                .domain
                .get(domain)
                .and_then(|ids| {
                    ids.iter()
                        .find_map(|&idx| port_matches(rules[idx].port, port).then_some(idx))
                })
                .map(|idx| &rules[idx]),
            TargetKind::Ipv4(ip) => {
                let mut best_idx: Option<usize> = None;
                if let Some(ids) = self.ipv4.get(ip) {
                    for &idx in ids {
                        if port_matches(rules[idx].port, port)
                            && best_idx.is_none_or(|best| idx < best)
                        {
                            best_idx = Some(idx);
                        }
                    }
                }
                let needle = u32::from(*ip);
                let bucket = ((needle >> 24) & 0xff) as usize;
                for &idx in &self.range_buckets[bucket] {
                    let rule = &rules[idx];
                    let HostMatcher::Ipv4Range(start, end) = &rule.matcher else {
                        continue;
                    };
                    if *start <= needle
                        && needle <= *end
                        && port_matches(rule.port, port)
                        && best_idx.is_none_or(|best| idx < best)
                    {
                        best_idx = Some(idx);
                    }
                }
                best_idx.map(|idx| &rules[idx])
            }
        }
    }
}

fn normalize_dns_servers(servers: Vec<String>) -> Vec<SocketAddr> {
    const DNS_DEFAULT_PORT: u16 = 53;

    let mut out = Vec::with_capacity(servers.len());
    let mut seen = HashSet::<SocketAddr>::with_capacity(servers.len());
    for raw in servers {
        let token = raw.trim();
        if token.is_empty() {
            continue;
        }
        let addr = if let Ok(addr) = token.parse::<SocketAddr>() {
            Some(addr)
        } else if let Ok(ip) = token.parse::<IpAddr>() {
            Some(SocketAddr::new(ip, DNS_DEFAULT_PORT))
        } else {
            None
        };
        let Some(addr) = addr else {
            continue;
        };
        if seen.insert(addr) {
            out.push(addr);
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

#[derive(Debug, Clone)]
struct DnsIndexes {
    scoped: HashMap<i32, HashMap<String, Vec<Ipv4Addr>>>,
    exact: HashMap<String, Vec<DnsDataRecord>>,
    record_count: usize,
}

fn build_dns_indexes(raw_dns_records: Vec<crate::route_table::DnsRecord>) -> DnsIndexes {
    let mut scoped = HashMap::<i32, HashMap<String, Vec<Ipv4Addr>>>::new();
    let mut exact = HashMap::<String, Vec<DnsDataRecord>>::new();
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
        scoped
            .entry(rec.rc_id)
            .or_default()
            .entry(host.clone())
            .or_default()
            .push(ip);
        exact.entry(host).or_default().push(DnsDataRecord {
            rc_id: rec.rc_id,
            ip,
        });
    }
    DnsIndexes {
        scoped,
        exact,
        record_count: seen_dns.len(),
    }
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
    fn dns_data_exact_host_can_route_without_rc_rule() {
        let table = RouteTable {
            rules: vec![],
            dns_servers: vec![],
            dns_records: vec![DnsRecord {
                rc_id: 244,
                host: "ecard.shiep.edu.cn".to_string(),
                ip: "10.168.103.76".to_string(),
            }],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        let plan = matcher.plan("ecard.shiep.edu.cn", 80);
        match plan {
            RoutePlan::Remote {
                dial,
                rc_id,
                rc_name,
                source,
            } => {
                assert_eq!(dial, "10.168.103.76:80");
                assert_eq!(rc_id, 244);
                assert_eq!(rc_name, "dns.data");
                assert_eq!(source, RouteSource::DnsData);
            }
            _ => panic!("expected remote plan"),
        }
    }

    #[test]
    fn dns_data_exact_host_does_not_override_reserved_proto1_rule() {
        let table = RouteTable {
            rules: vec![RouteRule {
                rc_id: -98,
                proto: 1,
                name: "__DNS_HIDE_RC1".to_string(),
                host: "210.35.88.5".to_string(),
                port: PortRange { start: 53, end: 53 },
            }],
            dns_servers: vec![],
            dns_records: vec![DnsRecord {
                rc_id: -98,
                host: "210.35.88.5".to_string(),
                ip: "210.35.88.5".to_string(),
            }],
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

    #[test]
    fn cname_alias_can_rematch_domain_rule() {
        let table = RouteTable {
            rules: vec![RouteRule {
                rc_id: 150,
                proto: 0,
                name: "SUEP-WAF".to_string(),
                host: "lgwf0-46.shiep.edu.cn".to_string(),
                port: PortRange {
                    start: 1,
                    end: 65535,
                },
            }],
            dns_servers: vec![],
            dns_records: vec![DnsRecord {
                rc_id: 150,
                host: "lgwf0-46.shiep.edu.cn".to_string(),
                ip: "10.166.64.6".to_string(),
            }],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        let plan = matcher
            .plan_from_cname_aliases(
                "estudent.shiep.edu.cn",
                443,
                &["lgwf0-46.shiep.edu.cn".to_string()],
            )
            .unwrap();
        match plan {
            RoutePlan::Remote {
                dial,
                rc_id,
                source,
                ..
            } => {
                assert_eq!(dial, "10.166.64.6:443");
                assert_eq!(rc_id, 150);
                assert_eq!(source, RouteSource::CnameDnsMap);
            }
            _ => panic!("expected remote plan"),
        }
    }

    #[test]
    fn cname_alias_rematch_never_promotes_ip_to_rule_match() {
        let table = RouteTable {
            rules: vec![RouteRule {
                rc_id: 150,
                proto: 0,
                name: "private-ip".to_string(),
                host: "10.166.64.6".to_string(),
                port: PortRange {
                    start: 1,
                    end: 65535,
                },
            }],
            dns_servers: vec![],
            dns_records: vec![],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        let plan = matcher.plan_from_cname_aliases(
            "estudent.shiep.edu.cn",
            443,
            &["10.166.64.6".to_string()],
        );
        assert!(plan.is_none());
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
                "114.114.114.114:53".to_string(),
                "210.35.88.5:53".to_string(),
            ],
            dns_records: vec![],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        assert_eq!(
            matcher.dns_servers,
            vec![
                "210.35.88.5:53".parse().unwrap(),
                "114.114.114.114:53".parse().unwrap()
            ]
        );
    }

    #[test]
    fn dns_servers_accept_ipv6_and_drop_invalid_entries() {
        let table = RouteTable {
            rules: vec![],
            dns_servers: vec![
                "::1".to_string(),
                "[::1]:53".to_string(),
                "not-a-server".to_string(),
            ],
            dns_records: vec![],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        assert_eq!(matcher.dns_servers, vec!["[::1]:53".parse().unwrap()]);
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
            dns_servers: vec!["127.0.0.1:1".to_string()],
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

    #[test]
    fn ip_match_preserves_original_rule_order_between_exact_and_range() {
        let table = RouteTable {
            rules: vec![
                RouteRule {
                    rc_id: 1,
                    proto: 0,
                    name: "range-first".to_string(),
                    host: "10.50.2.1~10.50.2.254".to_string(),
                    port: PortRange { start: 80, end: 80 },
                },
                RouteRule {
                    rc_id: 2,
                    proto: 0,
                    name: "exact-second".to_string(),
                    host: "10.50.2.206".to_string(),
                    port: PortRange { start: 80, end: 80 },
                },
            ],
            dns_servers: vec![],
            dns_records: vec![],
        };
        let matcher = RouteMatcher::from_table(table).unwrap();
        let plan = matcher.plan("10.50.2.206", 80);
        match plan {
            RoutePlan::Remote { rc_id, dial, .. } => {
                assert_eq!(rc_id, 1);
                assert_eq!(dial, "10.50.2.206:80");
            }
            _ => panic!("expected remote plan"),
        }
    }
}
