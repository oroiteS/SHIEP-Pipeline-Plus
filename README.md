# SHIEP-Pipeline-Plus

[SHIEP-Pipeline](https://github.com/Yan233th/SHIEP-Pipeline) 的 fork，在原版基础上增加了 `--extra` 功能。

## 与原版的区别

原版的 split-routing 完全依赖服务端下发的 route table。如果某个 IP 不在表中（例如学校内网的非标端口服务），流量会被 fallback 到直连或上游代理，导致无法通过 VPN 隧道访问。

本 fork 新增以下功能：

### `--extra <IP>`：手动白名单 IP

允许手动将额外 IP 加入隧道路由白名单，支持三种格式。

> **注意**：`--extra` 仅修改本地路由逻辑，不改变服务端策略。实测中 VPN 服务器可能仍拒绝转发额外 IP 的流量。此功能仅做路由层面的能力扩展。

| 格式      | 示例                      |
| --------- | ------------------------- |
| 单个 IP   | `--extra 1.1.1.1`         |
| IP 范围   | `--extra 1.1.1.1~1.1.1.2` |
| CIDR 网段 | `--extra 1.1.1.0/24`      |

可多次指定：`--extra 1.1.1.1 --extra 192.168.1.0/24`

### `--details`：输出路由表详情

启用后，将服务端下发的路由表（IP 规则、域名规则、DNS 记录、Extra IP）写入当前目录的 `route-details.txt`。终端仅显示一行简要提示，不会占用过多缓冲区。

```bash
SHIEP-Pipeline --server ... --username ... --password ... --extra ... --details
```

## 使用

```bash
# 从源码运行
cargo run -p ec-cli -- \
  --server <VPN_SERVER> \
  --username <USERNAME> \
  --password <PASSWORD> \
  --extra <IP>

# 完整参数
./SHIEP-Pipeline \
  --server <VPN_SERVER> \
  --username <USERNAME> \
  --password <PASSWORD> \
  --bind 127.0.0.1:1080 \
  --fallback socks5h://127.0.0.1:114514 \
  --extra <IP>
```

默认 SOCKS5 监听地址：`127.0.0.1:1080`。

所有参数的详细说明见原版 README。

## 致谢

- [SHIEP-Pipeline](https://github.com/Yan233th/SHIEP-Pipeline) — 原版项目作者
- [NJUConnect](https://github.com/lyc8503/NJUConnect) / [EasierConnect](https://github.com/Yan233th/EasierConnect) — 上游参考项目

## Issues

本 fork 仅做增量修改，不计划长期维护。如遇 bug，建议先去[原版仓库](https://github.com/Yan233th/SHIEP-Pipeline/issues)提交 issue。
