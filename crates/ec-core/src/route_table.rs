use crate::endpoint::parse_server;
use crate::error::{EcError, EcResult};
use openssl::ssl::{SslConnector, SslMethod, SslOptions, SslVerifyMode};
use quick_xml::Reader;
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::QName;
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct RouteTable {
    pub rules: Vec<RouteRule>,
    #[allow(dead_code)]
    pub dns_servers: Vec<String>,
    pub dns_records: Vec<DnsRecord>,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct RouteRule {
    pub rc_id: i32,
    pub name: String,
    pub host: String,
    pub port: PortRange,
}

#[allow(dead_code)]
#[derive(Debug, Clone, Copy)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct DnsRecord {
    pub rc_id: i32,
    pub host: String,
    pub ip: String,
}

pub fn fetch_route_table(server: &str, twf_id: &str) -> EcResult<RouteTable> {
    let (authority, host) = parse_server(server)?;
    let mut stream = connect_tls(&authority, &host)?;
    let request = format!(
        "GET /por/rclist.csp HTTP/1.1\r\nHost: {authority}\r\nCookie: TWFID={twf_id}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| EcError::Runtime(format!("rclist request write failed: {e}")))?;

    let mut buf = [0u8; 4096];
    let mut raw = Vec::new();
    let deadline = Instant::now() + Duration::from_secs(8);
    while Instant::now() < deadline {
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => raw.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == ErrorKind::WouldBlock || e.kind() == ErrorKind::TimedOut => {
                break;
            }
            Err(e) => {
                return Err(EcError::Runtime(format!(
                    "rclist response read failed: {e}"
                )));
            }
        }
    }
    if raw.is_empty() {
        return Err(EcError::Runtime(
            "rclist response is empty or timed out".to_string(),
        ));
    }

    let text = String::from_utf8_lossy(&raw);
    let xml_start = text.find("<?xml").or_else(|| text.find("<Resource>"));
    let Some(start) = xml_start else {
        return Err(EcError::Runtime(
            "rclist response does not contain XML payload".to_string(),
        ));
    };
    let xml_payload = &text[start..];
    dump_route_table_snapshot(xml_payload);
    parse_route_table_xml(xml_payload)
}

fn dump_route_table_snapshot(xml_payload: &str) {
    let path = Path::new("target/.internal/rclist.latest.xml");
    if let Some(parent) = path.parent()
        && let Err(err) = fs::create_dir_all(parent)
    {
        eprintln!("[APP][DEBUG] rclist snapshot mkdir failed: {err}");
        return;
    }
    if let Err(err) = fs::write(path, xml_payload) {
        eprintln!("[APP][DEBUG] rclist snapshot write failed: {err}");
        return;
    }
    eprintln!("[APP][DEBUG] rclist snapshot saved: {}", path.display());
}

fn connect_tls(authority: &str, host: &str) -> EcResult<openssl::ssl::SslStream<TcpStream>> {
    let tcp = TcpStream::connect(authority)
        .map_err(|e| EcError::Runtime(format!("rclist tcp connect failed: {e}")))?;
    tcp.set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| EcError::Runtime(format!("set read timeout failed: {e}")))?;
    tcp.set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| EcError::Runtime(format!("set write timeout failed: {e}")))?;

    let mut builder = SslConnector::builder(SslMethod::tls_client())
        .map_err(|e| EcError::Runtime(format!("rclist tls builder create failed: {e}")))?;
    builder.set_verify(SslVerifyMode::NONE);
    builder.set_options(SslOptions::NO_TICKET);
    let connector = builder.build();

    let mut config = connector
        .configure()
        .map_err(|e| EcError::Runtime(format!("rclist tls configure failed: {e}")))?;
    config.set_verify_hostname(false);
    let ssl = config
        .into_ssl(host)
        .map_err(|e| EcError::Runtime(format!("rclist tls prepare failed: {e}")))?;
    ssl.connect(tcp)
        .map_err(|e| EcError::Runtime(format!("rclist tls handshake failed: {e}")))
}

fn parse_route_table_xml(xml: &str) -> EcResult<RouteTable> {
    let mut reader = Reader::from_str(xml);
    reader.config_mut().trim_text(true);
    let mut buf = Vec::new();

    let mut rules = Vec::<RouteRule>::new();
    let mut dns_servers = Vec::<String>::new();
    let mut dns_records = Vec::<DnsRecord>::new();

    loop {
        match reader.read_event_into(&mut buf) {
            Ok(Event::Start(ref e)) | Ok(Event::Empty(ref e)) => match e.name() {
                QName(b"Rc") => parse_rc(e, &reader, &mut rules)?,
                QName(b"Dns") => parse_dns(e, &reader, &mut dns_servers, &mut dns_records)?,
                _ => {}
            },
            Ok(Event::Eof) => break,
            Ok(_) => {}
            Err(e) => return Err(EcError::Runtime(format!("rclist xml parse failed: {e}"))),
        }
        buf.clear();
    }

    Ok(RouteTable {
        rules,
        dns_servers,
        dns_records,
    })
}

fn parse_rc(
    e: &BytesStart<'_>,
    reader: &Reader<&[u8]>,
    rules: &mut Vec<RouteRule>,
) -> EcResult<()> {
    let Some(id_raw) = attr_value(e, reader, b"id")? else {
        return Ok(());
    };
    let Some(host_raw) = attr_value(e, reader, b"host")? else {
        return Ok(());
    };
    let Some(port_raw) = attr_value(e, reader, b"port")? else {
        return Ok(());
    };

    let rc_id = id_raw
        .parse::<i32>()
        .map_err(|e| EcError::Runtime(format!("invalid rc id '{id_raw}': {e}")))?;
    let name = attr_value(e, reader, b"name")?.unwrap_or_default();
    let hosts = split_hosts(&host_raw);
    let ports = split_ports(&port_raw);
    if hosts.is_empty() || ports.is_empty() {
        return Ok(());
    }

    let width = hosts.len().max(ports.len());
    for idx in 0..width {
        let host = hosts[idx.min(hosts.len() - 1)].clone();
        let port = ports[idx.min(ports.len() - 1)];
        rules.push(RouteRule {
            rc_id,
            name: name.clone(),
            host,
            port,
        });
    }
    Ok(())
}

fn parse_dns(
    e: &BytesStart<'_>,
    reader: &Reader<&[u8]>,
    dns_servers: &mut Vec<String>,
    dns_records: &mut Vec<DnsRecord>,
) -> EcResult<()> {
    if let Some(servers) = attr_value(e, reader, b"dnsserver")? {
        for token in servers.split(';') {
            let s = token.trim();
            if !s.is_empty() {
                dns_servers.push(s.to_string());
            }
        }
    }
    if let Some(data) = attr_value(e, reader, b"data")? {
        for token in data.split(';') {
            let item = token.trim();
            if item.is_empty() {
                continue;
            }
            let mut parts = item.splitn(3, ':');
            let Some(id_raw) = parts.next() else {
                continue;
            };
            let Some(host_raw) = parts.next() else {
                continue;
            };
            let Some(ip_raw) = parts.next() else {
                continue;
            };
            let Ok(rc_id) = id_raw.parse::<i32>() else {
                continue;
            };
            let host = normalize_host_token(host_raw);
            let ip = ip_raw.trim().to_string();
            if host.is_empty() || ip.is_empty() {
                continue;
            }
            dns_records.push(DnsRecord { rc_id, host, ip });
        }
    }
    Ok(())
}

fn attr_value(e: &BytesStart<'_>, reader: &Reader<&[u8]>, key: &[u8]) -> EcResult<Option<String>> {
    for attr in e.attributes().with_checks(false) {
        let attr = attr.map_err(|e| EcError::Runtime(format!("xml attr parse failed: {e}")))?;
        if attr.key == QName(key) {
            let value = attr
                .decode_and_unescape_value(reader.decoder())
                .map_err(|e| EcError::Runtime(format!("xml attr decode failed: {e}")))?;
            return Ok(Some(value.into_owned()));
        }
    }
    Ok(None)
}

fn split_hosts(raw: &str) -> Vec<String> {
    raw.split(';')
        .map(normalize_host_token)
        .filter(|h| !h.is_empty())
        .collect()
}

fn normalize_host_token(raw: &str) -> String {
    let mut token = raw.trim();
    token = token
        .strip_prefix("http://")
        .or_else(|| token.strip_prefix("https://"))
        .unwrap_or(token);
    token.split('/').next().unwrap_or("").trim().to_string()
}

fn split_ports(raw: &str) -> Vec<PortRange> {
    raw.split(';')
        .filter_map(|token| {
            let t = token.trim();
            if t.is_empty() {
                return None;
            }
            if let Some((a, b)) = t.split_once('~') {
                let Ok(start) = a.trim().parse::<u16>() else {
                    return None;
                };
                let Ok(end) = b.trim().parse::<u16>() else {
                    return None;
                };
                return Some(PortRange { start, end });
            }
            let Ok(port) = t.parse::<u16>() else {
                return None;
            };
            Some(PortRange {
                start: port,
                end: port,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{parse_route_table_xml, split_hosts, split_ports};

    #[test]
    fn split_hosts_normalizes_scheme_and_path() {
        let hosts = split_hosts("http://a.example/x;https://b.example;y.example");
        assert_eq!(
            hosts,
            vec![
                "a.example".to_string(),
                "b.example".to_string(),
                "y.example".to_string()
            ]
        );
    }

    #[test]
    fn split_ports_parses_ranges() {
        let ports = split_ports("80~80;443~445;53");
        assert_eq!(ports.len(), 3);
        assert_eq!(ports[0].start, 80);
        assert_eq!(ports[1].end, 445);
        assert_eq!(ports[2].start, 53);
        assert_eq!(ports[2].end, 53);
    }

    #[test]
    fn parse_xml_extracts_rules_and_dns() {
        let xml = r#"<?xml version="1.0" encoding="utf-8"?>
<Resource>
  <Rcs>
    <Rc id="205" name="IDS" host="ids.shiep.edu.cn;10.1.2.3" port="443~443;80~80" />
  </Rcs>
  <Dns dnsserver="210.35.88.5;114.114.114.114" data="205:ids.shiep.edu.cn:10.166.35.11;" />
</Resource>"#;
        let table = parse_route_table_xml(xml).unwrap();
        assert_eq!(table.rules.len(), 2);
        assert_eq!(table.dns_servers.len(), 2);
        assert_eq!(table.dns_records.len(), 1);
        assert_eq!(table.dns_records[0].host, "ids.shiep.edu.cn");
        assert_eq!(table.dns_records[0].ip, "10.166.35.11");
    }
}
