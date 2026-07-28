# 使用 Hermes 管理与维护旁路由

本项目可以由 [Hermes Agent](https://hermes-agent.nousresearch.com/docs) 作为运维助手进行日常管理、诊断、修复和文档维护。

> Hermes 是**额外安装和单独配置**的 AI 运维工具，不属于 `./install.sh` 的必装依赖。旁路由安装器不会自动安装 Hermes，也不会替你配置模型 Provider、API 凭据或消息平台。

## Hermes 能做什么

在 Hermes 已获得本机终端和文件工具权限的前提下，它可协助：

| 范围 | 示例 |
|---|---|
| 健康检查 | 检查 `mihomo`、`mosdns`、`adguardhome`、TProxy、nftables、策略路由和近期错误日志 |
| 数据平面验证 | 重复验证国内 DNS、全球代理 DNS、Google、TCP/UDP TProxy 与广告过滤路径 |
| 节点与订阅 | 检查订阅更新、Provider 健康、首选节点恢复与故障转移状态 |
| Web 与 AdGuard | 检查 Web 服务、认证问题、AdGuard 查询/过滤命中和误杀 |
| 维护操作 | 在先备份、先校验、可回滚的前提下执行服务重启、规则重载、升级或回滚 |
| 项目维护 | 更新模板、文档、测试、发布包和 GitHub CI，并运行本项目门禁 |
| 定期巡检 | 使用 Hermes 的 cron 功能创建健康巡检、订阅检查或日志摘要任务 |

## 安装 Hermes

请遵循 Hermes 官方文档安装和配置：

```bash
curl -fsSL https://hermes-agent.nousresearch.com/install.sh | bash
hermes setup
hermes doctor
```

选择模型/Provider 后，建议只授予实际需要的工具权限。生产旁路由上至少应保留人工控制台或其他带外访问路径，不能把 AI 工具作为唯一恢复渠道。

## 在项目目录中工作

从项目根目录启动 Hermes：

```bash
cd /path/to/bypass-router-project
hermes
```

仓库中的 [`.hermes.md`](../.hermes.md) 会为 Hermes 提供项目规则，包括：

- 不修改主路由或全网 DHCP，除非管理员明确授权；
- 配置改动前先校验并保留恢复路径；
- 公网 DNS 必须保持加密且 fail closed；
- 不能仅凭 `systemctl active` 或一次 HTTP 成功宣称网络正常；
- 不将订阅 URL、Token、密码、节点凭据或流量记录写入仓库、日志或文档。

## 推荐提问方式

向 Hermes 提供具体目标和范围，例如：

```text
只读检查当前旁路由：确认核心服务、nftables、ip rule、DNS 加密上游，
并对百度、Google 和一个 LAN 客户端路径做重复数据平面测试；不要修改配置。
```

```text
Mihomo 订阅更新失败。先读取近期失败日志、订阅管理状态和 Provider 文件，
定位根因；先备份，再只做必要修复，修复后验证订阅和首选节点顺序。
```

```text
对本项目运行 scan、pytest、routerctl validate、generate 和 release 校验；
不要部署到生产路径。
```

## 生产变更约束

适合授权 Hermes 执行的常见操作：

- 重新加载经校验的配置；
- 重启单个旁路由服务；
- 更新订阅、规则或广告过滤器；
- 执行项目已有的 `routerctl status`、`upgrade`、`rollback`；
- 在出现明确故障证据后修复 TProxy、DNS 或服务依赖。

以下操作应先取得管理员明确授权：

- 修改主路由、DHCP 或全网 DNS；
- 变更 LAN 网段、旁路由本机 IP、上游网关或 SSH 管理路径；
- 大范围放行防火墙；
- 删除备份、密钥、订阅或历史状态；
- 将真实秘密、生产配置或日志发送到第三方。

## 验收标准

Hermes 执行维护后应报告实际证据，而不是只报告服务状态：

1. 变更前的备份或恢复点；
2. 配置/语法校验结果；
3. 服务、监听端口、nftables 与策略路由状态；
4. 重复的数据平面 DNS、国内、代理和 TCP/UDP 验证结果；
5. 近期错误日志；
6. 失败时的回滚结果和后续恢复命令。

## 自动化巡检

Hermes 可以使用 cron 创建**只读**定时巡检或摘要任务。建议初期只告警、不自动修复；确认监测指标稳定后，再对已有备份和回滚策略的低风险操作授权自动恢复。

```bash
hermes cron list
```

关于 Hermes 的 cron、gateway、权限和配置，请以[官方文档](https://hermes-agent.nousresearch.com/docs)为准。

## 安全提示

- 不要把模型 API Key、GitHub Token、订阅 URL 或 Web 密码直接发送给 Hermes；使用其认证/配置机制或本机受限文件；
- 使用 Telegram、Discord 等消息平台管理旁路由时，应启用配对/访问控制；
- 生产系统应保留独立于 Hermes 的 SSH、控制台或 Tailscale 恢复通道；
- 任何自动修复都应遵守本项目的 DNS 加密、故障阈值、冷却时间和首选节点策略。

---

Hermes 是辅助运维控制面；项目中的 `routerctl`、systemd、nftables 与可验证的实际网络数据仍是变更和验收的基础。
