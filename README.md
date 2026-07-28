# Debian 可复制旁路由项目

> **面向 Debian 13 的参数化家庭旁路由部署项目**：集成 Mihomo、MosDNS、AdGuard Home、nftables/TProxy、systemd 与 Web 控制台。
>
> 当前状态：**已通过本地、隔离生命周期和 CI 校验；尚未完成干净 Debian 13 虚拟机的全链路验收，因此不是 release-ready。**

[![CI](https://github.com/wtice9527/bypass-router-project/actions/workflows/ci.yml/badge.svg)](https://github.com/wtice9527/bypass-router-project/actions/workflows/ci.yml)

## 核心优势

### 1. 降低旁路由部署与维护门槛

- 通过交互向导填写接口、网段、本机 IP、上游网关、订阅和 Web 密码，无需从零拼装 Mihomo、MosDNS、AdGuard Home、nftables 与 systemd；
- 缺失的核心组件、运行/状态目录、服务与定时任务可由安装器自动准备；
- 提供 Web 控制台管理节点、订阅、规则、AdGuard、服务、透明代理与诊断；
- 提供 `validate`、`generate`、`install`、`upgrade`、`rollback`、`uninstall`、`status` 等完整生命周期入口。

### 2. Hermes AI 辅助运维：让排障有上下文、有证据

Hermes 可以作为**可选的辅助运维控制面**：读取当前配置、服务、nftables、策略路由和近期日志，结合真实 DNS、国内站点、Google 代理、TCP/UDP TProxy 数据平面测试定位问题；在获得授权后执行先备份、先校验、可回滚的维护操作。

这意味着日常维护不必完全依赖手工记忆命令和配置位置，尤其适合订阅异常、节点更新、DNS/规则问题、广告误杀、服务依赖或 TProxy 异常的排查。Hermes 不替代管理员和带外恢复通道；它的结论仍应以实时系统状态和实际数据平面验证为准。详见：[使用 Hermes 管理与维护旁路由](docs/HERMES_OPERATIONS.md)。

### 3. 对可识别的小故障进行受控自我修复

Watchdog 定期检查核心服务、直连网络、国内/全球 DNS、严格 DNS 配置、Google 代理、TProxy 和可选的 Tailscale 状态。发现可恢复问题时，会按依赖顺序尝试重启必要组件并再次验证：

- 单次 Google 代理失败只记录，不立即重启；
- 连续失败达到阈值（默认 3 次）才尝试修复；
- 修复后进入冷却期（默认 900 秒），避免重复重启；
- 修复结果会再次执行检查，未恢复会明确报告为未完全成功。

这不是“无条件自动修复”：网络拓扑、主路由 DHCP、LAN 地址、上游网关、大范围防火墙放行和其他高影响变更不应自动执行。

### 4. 从设计上降低 DNS 泄露风险

- 国内域名使用加密国内 DoH；全球域名通过 Mihomo 使用加密 DoH；
- 公网 DNS 上游只允许 DoH/DoT，**不配置公网 UDP/TCP 53 fallback**；
- AdGuard Home 只转发到本地 MosDNS，没有独立公网 fallback；
- nftables 接管目标 LAN 客户端的 DNS 53 流量，降低客户端自行指定明文 DNS 绕过的概率；
- 配置与 Watchdog 均检查严格 DNS 不变量；上游不可用时应失败关闭，而不是静默降级到明文 DNS。

> DNS 泄露防护的前提是客户端实际使用旁路由作为网关/DNS，且未自行启用浏览器 Secure DNS、Android 私人 DNS、IPv6 旁路或独立应用代理。部署后应在客户端侧进行泄露检测和实际验证。

### 5. 稳定性与可恢复性

- TCP 使用 Redirect、UDP 使用 TProxy；
- 常用节点健康时保持，故障后才切备用，恢复后可重新应用首选顺序；
- 代理全部不可用时，用户流量可按策略临时回退 DIRECT；DNS 仍保持加密/fail-closed，两者不混淆；
- 安装与升级记录 manifest、创建备份，支持回滚、卸载和文件漂移检查；
- 发布前运行测试、敏感信息扫描、模板渲染与配置检查。

### 6. 安全与隐私边界

- 发布目录不包含订阅、节点、Token、密码、私钥或原生产网络身份；
- `secrets.json` 与非秘密配置分离，创建时使用 `0600` 权限；
- 订阅 URL 仅允许 HTTPS，并对重定向进行安全校验；
- Mihomo Controller 仅监听回环；Web 写操作要求认证与 CSRF，外部数据进行 HTML 转义；
- 项目不修改主路由 DHCP，也不会自动把全网设备切换到旁路由。

## 适用范围与前提

| 项目 | 要求 |
|---|---|
| 系统 | Debian 13；IPv4 LAN |
| 架构 | `amd64` 或 `arm64`（自动获取核心二进制） |
| 权限 | 安装需要 `root` / `sudo` |
| 网络 | 安装时可访问 Debian 软件源与 GitHub Releases |
| 带外访问 | 强烈建议保留虚拟机/物理控制台或已可用的 Tailscale |
| 客户端接管 | 仅把网关和 DNS 设置为旁路由 IP 的客户端会进入旁路由路径 |

> 项目**不会修改主路由 DHCP**，也不会自动把全网设备切换到旁路由。

## 5 分钟交互部署

```bash
git clone https://github.com/wtice9527/bypass-router-project.git
cd bypass-router-project
sudo ./install.sh
```

安装器会：

1. 检查 Debian 与 root 权限；
2. 安装基础依赖并创建 Python 虚拟环境；
3. 交互收集参数、校验输入并显示摘要；
4. 在缺失时下载 Mihomo、MosDNS、AdGuard Home，并校验上游 SHA-256 digest；
5. 写入配置、创建运行/状态目录、启用服务、应用订阅；
6. 输出 Web 访问地址和恢复入口。

### 向导需要你确认的内容

| 类别 | 参数 |
|---|---|
| 网络 | LAN 接口、LAN CIDR、旁路由本机 IPv4、上游网关 |
| 管理 | Web 监听地址/端口、当前 sshd 监听端口、Tailscale 管理访问 |
| DNS | 国内加密 DoH、全球代理 DoH |
| 代理 | HTTPS 订阅 URL、健康检测 URL |
| 稳定性 | Watchdog 连续失败阈值、冷却时间 |
| 安全 | Web 管理密码（无回显输入、二次确认、至少 12 字符） |
| 可选高影响动作 | 是否由 NetworkManager 修改本机静态 IPv4（默认**否**） |

完整流程与风险说明见：[交互部署指南](docs/INTERACTIVE_INSTALL.md)。

## Web 管理控制台

部署完成后，可通过 Web 控制台管理节点、订阅、规则、AdGuard、服务、透明代理与诊断。

![旁路由控制台登录页](docs/screenshots/web-login.png)

> 示例截图不包含真实密码、订阅、节点、IP 地址或流量数据。控制台地址为 `http://旁路由IP:Web端口`。

## 部署后：让客户端使用旁路由

安装成功不代表客户端已经走旁路由。需要在目标客户端手动设置：

```text
IPv4 网关 = 旁路由本机 IPv4
DNS       = 旁路由本机 IPv4
```

确认稳定后，如需全网接管，请由管理员自行在主路由 DHCP 中做配置；这不属于安装器的自动操作范围。

## 访问与检查

Web 控制台地址：

```text
http://旁路由IP:Web端口
```

常用检查命令：

```bash
sudo .venv/bin/routerctl status
systemctl --no-pager --full status mihomo mosdns adguardhome \
  bypass-router-tproxy bypass-router-web
ip rule show
ip route show table 100
sudo nft list table inet bypass_router
```

## 不使用交互模式

高级用户或 CI 可自行准备 `config.json` 与 `secrets.json`：

```bash
python3 -m venv .venv
.venv/bin/pip install -e .

# 校验，不写入系统
.venv/bin/routerctl validate -c config.json -s secrets.json
.venv/bin/routerctl generate -c config.json -o build/rootfs

# 在临时目录演练完整生命周期
TMP=$(mktemp -d)
.venv/bin/routerctl install -c config.json -s secrets.json --prefix "$TMP" --yes
.venv/bin/routerctl status --prefix "$TMP"
.venv/bin/routerctl upgrade -c config.json -s secrets.json --prefix "$TMP" --yes
.venv/bin/routerctl rollback --prefix "$TMP" --yes
.venv/bin/routerctl uninstall --prefix "$TMP" --yes

# 生产安装（必须保留带外管理通道）
sudo .venv/bin/routerctl install -c config.json -s secrets.json --yes
```

## 配置与秘密

- `config.json`：网络、端口、DNS、策略路由、Watchdog 等非秘密参数；
- `secrets.json`：订阅 URL 与 Web 管理密码；由向导创建时权限为 `0600`；
- 两个文件均被 Git 忽略；**不要提交、截图或粘贴到 Issue。**

配置样例：

```text
config.example.json
secrets.example.json
```

## 生命周期命令

| 命令 | 作用 |
|---|---|
| `routerctl wizard` | 交互生成配置；加 `--install --bootstrap` 可执行完整安装 |
| `routerctl validate` | 校验参数、模板与可用的原生检查器 |
| `routerctl generate` | 生成脱敏 rootfs，不修改系统 |
| `routerctl install` | 备份、安装、启用服务并记录 manifest |
| `routerctl upgrade` | 备份当前版本、覆盖并清理旧文件 |
| `routerctl rollback` | 恢复指定或最近备份 |
| `routerctl uninstall` | 删除 manifest 管理的文件并保留恢复点 |
| `routerctl status` | 检查版本、文件漂移和服务状态 |

## 安全边界

- 订阅 URL 只允许 HTTPS；
- Web 密码使用 scrypt 哈希保存；
- Mihomo Controller 只监听回环；
- 公网 DNS 仅允许 DoH/DoT，没有明文 53 fallback；
- 外部数据在 Web 前端转义，写操作要求认证和 CSRF；
- 发布前 CI 执行测试、敏感信息扫描、模板渲染、Python/JavaScript/nftables 检查；
- 生产安装会修改防火墙、策略路由、DNS 与服务状态，务必保留带外管理。

漏洞报告方式请见 [SECURITY.md](SECURITY.md)。

## 文档导航

- [交互部署指南](docs/INTERACTIVE_INSTALL.md)
- [使用 Hermes 管理与维护旁路由](docs/HERMES_OPERATIONS.md)
- [架构说明](docs/architecture.md)
- [验收清单与已知边界](docs/ACCEPTANCE.md)
- [贡献指南](CONTRIBUTING.md)
- [安全策略](SECURITY.md)

## 许可证

[MIT](LICENSE)
