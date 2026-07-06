# SHIEP-Pipeline-Plus

[SHIEP-Pipeline](https://github.com/Yan233th/SHIEP-Pipeline) 的 fork，基于上游 v2.0.0，并保留 Plus 路由和配置扩展。

## 与上游的区别

Plus 保留上游 v2.0.0 的协议、日志、SOCKS5、UDP ASSOCIATE、路由表降级和 debug 诊断行为，并额外提供以下参数：

- `--extra <IP>`：手动添加额外 IPv4 隧道路由，可重复指定。
- `--details`：成功获取路由表后，将规则和 DNS 记录写入 `route-details.txt`。
- `--remember`：记住 `--server` 和 `--username` 到 `remembered.json`，不会保存密码。

`--extra` 支持三种格式：

| 格式 | 示例 |
| --- | --- |
| 单个 IP | `--extra 10.50.2.206` |
| IP 范围 | `--extra 10.50.2.1~10.50.2.254` |
| CIDR 网段 | `--extra 10.50.2.0/24` |

> 注意：`--extra` 只改变本地路由选择，不改变服务端策略。VPN 服务端仍可能拒绝转发额外目标。

## Quick Start

```bash
SHIEP_PIPELINE_PASSWORD=<PASSWORD> ./SHIEP-Pipeline \
  --server <VPN_SERVER> \
  --username <USERNAME>
```

也可以直接传入密码，但不推荐，因为进程参数可能被系统上其他用户看到：

```bash
./SHIEP-Pipeline --server <VPN_SERVER> --username <USERNAME> --password <PASSWORD>
```

使用 Plus 参数：

```bash
SHIEP_PIPELINE_PASSWORD=<PASSWORD> ./SHIEP-Pipeline \
  --server <VPN_SERVER> \
  --username <USERNAME> \
  --bind 127.0.0.1:1080 \
  --fallback socks5h://127.0.0.1:114514 \
  --extra 10.50.2.206 \
  --extra 10.50.2.0/24 \
  --details \
  --remember
```

再次使用已保存的 server 和 username：

```bash
SHIEP_PIPELINE_PASSWORD=<PASSWORD> ./SHIEP-Pipeline --remember
```

## CLI Arguments

- `--server` VPN server address；未使用 `--remember` 时必需。
- `--username` VPN username；未使用 `--remember` 时必需。
- `SHIEP_PIPELINE_PASSWORD` required unless `--password` is provided。
- `--password` VPN password；可替代 `SHIEP_PIPELINE_PASSWORD`，但不推荐。
- `--bind` local bind address，默认 `127.0.0.1:1080`。
- `--fallback` fallback upstream proxy address。
- `--extra <IP>` extra IPv4/CIDR/range tunnel route，可重复指定。
- `--details` write `route-details.txt` after fetching the route table。
- `--remember` remember server and username in `remembered.json`。

Debug builds expose an additional `--debug` flag. Release builds do not include this flag or the diagnostic strings.

## Routing and Fallback

- VPN 启动后自动从 `/por/rclist.csp` 获取并解析路由规则。
- 如果路由表规则、DNS 记录、DNS server lookup、CNAME 或 IP range 匹配，流量走远程隧道。
- 如果目标 IPv4 命中 `--extra`，流量走远程隧道，日志 source 为 `extra-ip`。
- 未命中白名单时，TCP 流量走 fallback。
- 指定 `--fallback` 时，TCP fallback 走上游代理。
- 未指定 `--fallback` 时，TCP fallback 直连。
- 如果路由表无法获取，上游 v2.0.0 行为会退化为全隧道模式，请求 source 为 `route-table-unavailable`。
- UDP ASSOCIATE 支持远程路由；UDP fallback 不支持。

Supported fallback proxy input formats:

| Input format | Interpreted as |
| --- | --- |
| `socks5://host:port` | SOCKS5 proxy |
| `socks5h://host:port` | SOCKS5 proxy with remote DNS |
| `http://host:port` | HTTP CONNECT proxy |
| `host:port` | Plain host/port, interpreted as `socks5h://host:port` |

## Development

```bash
SHIEP_PIPELINE_PASSWORD=<PASSWORD> cargo run -p ec-cli -- \
  --server <VPN_SERVER> \
  --username <USERNAME>
```

Debug diagnostics:

```bash
SHIEP_PIPELINE_PASSWORD=<PASSWORD> cargo run -p ec-cli -- \
  --server <VPN_SERVER> \
  --username <USERNAME> \
  --debug
```

## Project Structure

- `crates/ec-cli`: CLI entry point and argument parsing
- `crates/ec-core`: Core implementation

## Acknowledgements

- [SHIEP-Pipeline](https://github.com/Yan233th/SHIEP-Pipeline) - upstream project
- [NJUConnect](https://github.com/lyc8503/NJUConnect) / [EasierConnect](https://github.com/Yan233th/EasierConnect) - upstream reference projects

## Issues

本 fork 仅做增量修改。如遇上游协议或核心运行时问题，建议先参考[原版仓库](https://github.com/Yan233th/SHIEP-Pipeline/issues)。
