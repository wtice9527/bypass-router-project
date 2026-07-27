# Debian 可复制旁路由项目

这是从一台实际运行的 Debian 13 家庭旁路由整理出的**参数化、脱敏、可生成、可安装、可升级、可回滚、可卸载**项目。

项目整合：

- Mihomo：规则分流、TCP Redirect、UDP TProxy、订阅与首选节点；
- MosDNS：国内加密 DoH 与全球代理 DoH，公网 DNS 无明文 53 回退；
- AdGuard Home：局域网 DNS 和保守广告过滤；
- nftables：DNS 接管、透明代理与默认拒绝输入防火墙；
- systemd：服务顺序、透明代理就绪等待、订阅更新和 Watchdog；
- Web 控制台：节点、订阅、规则、AdGuard、服务、透明代理和诊断管理。

## 安全承诺

发布目录不包含：

- 订阅 URL 或 Token；
- 节点服务器、UUID、密码、私钥；
- Web 管理密码；
- 原生产机器 IP、Tailscale IP 或节点名称。

真实秘密只允许放在本机 `secrets.json` 中。该文件已被 `.gitignore` 排除，不进入生成包、日志或 manifest。

## 快速开始

推荐在干净 Debian 13 主机直接运行交互部署：

```bash
git clone https://github.com/wtice9527/bypass-router-project.git
cd bypass-router-project
sudo ./install.sh
```

向导会自动探测接口、本机 IPv4、LAN 网段和上游网关，并询问 Web/SSH 端口、加密 DNS、订阅 URL、管理密码、Watchdog 策略，以及是否由 NetworkManager 配置本机静态 IP。完整说明见 [`docs/INTERACTIVE_INSTALL.md`](docs/INTERACTIVE_INSTALL.md)。

只生成配置、不安装系统：

```bash
python3 -m venv .venv
.venv/bin/pip install -e .
.venv/bin/routerctl wizard
```

编辑 `config.json` 和 `secrets.json` 后：

```bash
# 参数、模板及原生配置校验
.venv/bin/routerctl validate -c config.json -s secrets.json

# 只生成脱敏 rootfs，不修改系统
.venv/bin/routerctl generate -c config.json -o build/rootfs

# 在临时目录模拟安装生命周期（推荐先做）
TMP=$(mktemp -d)
.venv/bin/routerctl install -c config.json -s secrets.json --prefix "$TMP" --yes
.venv/bin/routerctl status --prefix "$TMP"
.venv/bin/routerctl upgrade -c config.json -s secrets.json --prefix "$TMP" --yes
.venv/bin/routerctl rollback --prefix "$TMP" --yes
.venv/bin/routerctl uninstall --prefix "$TMP" --yes

# 生产安装：必须保留控制台或 Tailscale 带外通道
sudo .venv/bin/routerctl install -c config.json -s secrets.json --yes
```

项目**不会修改主路由 DHCP**。只有把 IPv4 网关和 DNS 显式设置为本机地址的客户端才进入旁路由路径。

## 参数边界

非秘密参数位于 `config.json`：

- LAN 网卡、LAN CIDR、旁路由地址、上游网关；
- 服务端口、fwmark、策略路由表；
- 国内和全球加密 DNS 上游；
- 代理健康检查、Watchdog 阈值和冷却时间；
- Web 监听地址与端口。

秘密位于 `secrets.json`：

```json
{
  "subscription_url": "https://example.invalid/subscription",
  "web_admin_password": "strong local password"
}
```

## 生命周期命令

| 命令 | 行为 |
|---|---|
| `validate` | 校验参数、模板、nftables、Mihomo、Python 和 JavaScript |
| `generate` | 生成不含真实 secrets 的 rootfs |
| `install` | 备份旧文件、暂存、安装、启用服务并写 manifest |
| `upgrade` | 按旧 manifest 备份，覆盖新版本，删除旧版本遗留文件 |
| `rollback` | 恢复指定或最近备份 |
| `uninstall` | 仅删除 manifest 管理的文件，保留可恢复备份 |
| `status` | 检查安装版本、文件漂移和服务状态 |
| `wizard` | 交互收集网络、DNS、代理、Web 和秘密参数，可选择直接安装 |

生产写入失败时，安装器会删除本次新写文件并恢复备份。

## 目录

```text
assets/       可原样复制的 Web、运维脚本和 MosDNS 规则数据
templates/    Mihomo/MosDNS/AdGuard/nftables/systemd 参数模板
routerctl/    渲染和生命周期管理 CLI
scripts/      发布门禁与敏感信息扫描
tests/        单元、渲染和隔离生命周期测试
docs/         架构、安装、验收和故障恢复文档
release/      版本化发布包（生成物）
```

## 当前验收等级

本版本目标是：

- 项目原型完整；
- 脱敏 rootfs 可生成；
- 配置校验和隔离目录生命周期可执行；
- 生产安装、升级、回滚和卸载入口已实现。

在一台**干净 Debian 13 虚拟机**完成真实重启、网络故障、全节点失效、DNS fail-closed 和卸载恢复测试后，才可标记为 release-ready。详见 [`docs/ACCEPTANCE.md`](docs/ACCEPTANCE.md)。

## 许可证

MIT
