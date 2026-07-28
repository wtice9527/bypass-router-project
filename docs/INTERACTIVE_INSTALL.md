# 交互部署指南

## 一键入口

在一台干净的 Debian 13 机器上：

```bash
git clone https://github.com/wtice9527/bypass-router-project.git
cd bypass-router-project
sudo ./install.sh
```

安装脚本会安装基础依赖、创建 Python 虚拟环境，然后启动交互向导。安装前必须保留虚拟机控制台、物理控制台或 Tailscale 带外管理路径。

## 向导收集的参数

| 参数 | 作用 | 是否自动探测 |
|---|---|---|
| LAN 网络接口 | nftables 接管流量的入口网卡 | 从默认路由探测 |
| LAN 网段 CIDR | 允许接管和管理访问的客户端网段 | 从接口 IPv4 探测 |
| 旁路由本机 IPv4 | 客户端配置的网关和 DNS 地址 | 从接口 IPv4 探测 |
| 上游主路由 IPv4 | 旁路由自身默认网关 | 从默认路由探测 |
| 是否配置静态 IPv4 | 是否由脚本修改 NetworkManager | 默认否 |
| Web 监听地址和端口 | 管理控制台入口 | 默认 `0.0.0.0:8443` |
| SSH 端口 | 输入防火墙需要保留的当前 sshd 监听端口 | 自动探测，无法探测时默认 22 |
| Tailscale 管理访问 | 是否允许 `100.64.0.0/10` 管理 Web | 默认是 |
| 国内 DoH | 国内域名的加密直连解析器 | 提供保守默认值 |
| 全球 DoH | 经代理访问的加密解析器 | 提供保守默认值 |
| 代理健康 URL | 节点和策略组健康检测 | 默认 Google 204 |
| Watchdog 阈值/冷却 | 防止短时故障造成重启循环 | 默认 3 次/900 秒 |
| Mihomo 订阅 URL | 获取节点 Provider | 必填，只允许 HTTPS |
| Web 管理密码 | Web 控制台登录 | 必填，至少 12 字符 |

所有网络、DNS、端口参数写入 `config.json`；订阅 URL 和密码写入权限为 `0600` 的 `secrets.json`。这两个文件均不会进入 Git 或发布包。

## 静态 IP 选择

向导默认**不修改本机网络地址**，只使用你填写的参数生成和安装旁路由组件。如果选择让脚本配置静态 IPv4：

1. 必须由 NetworkManager 管理目标接口；
2. 脚本在服务和配置安装完成后才执行 `nmcli connection modify/up`；
3. SSH 会话可能在切换 IP 时中断；
4. 使用新填写的旁路由 IP 重新连接；
5. 主路由 DHCP 不会被修改。

## 自动安装内容

脚本会检查并在缺失时安装：

- Debian 软件包：Python、venv、pip、nftables、iproute2、curl、CA 证书、unzip、NetworkManager、Node.js；
- Mihomo 最新稳定版；
- MosDNS 最新稳定版；
- AdGuard Home 最新稳定版；
- 项目配置、systemd unit、Watchdog、Web 控制台和管理脚本；
- 订阅预检和 Provider 应用；
- IPv4 forwarding 与 `rp_filter=0` 持久 sysctl；
- systemd 服务和定时任务。

## 部署后客户端配置

项目不会修改主路由 DHCP。需要使用旁路由的客户端手动设置：

```text
IPv4 网关 = 旁路由本机 IPv4
DNS       = 旁路由本机 IPv4
```

也可以在确认运行稳定后，由用户自行修改主路由 DHCP；安装器不会自动执行这一高影响操作。

## 部署后检查

```bash
sudo .venv/bin/routerctl status
systemctl --no-pager --full status mihomo mosdns adguardhome bypass-router-tproxy bypass-router-web
ip rule show
ip route show table 100
sudo nft list table inet bypass_router
```

浏览器访问：

```text
http://旁路由IP:Web端口
```

## 恢复

```bash
sudo .venv/bin/routerctl rollback --yes
sudo .venv/bin/routerctl uninstall --yes
```

回滚会恢复安装前文件和 systemd 启用状态。若静态 IP 已由 NetworkManager 切换，需通过控制台手动恢复旧连接参数；网络管理变更不自动纳入文件级回滚。正式生产部署前应记录原始 `nmcli connection show <name>` 输出。

## 当前限制

- 仅支持 Debian 和 IPv4 LAN；
- 仅支持 amd64/arm64 自动下载二进制；
- 自动配置静态 IP 仅支持 NetworkManager；
- 二进制使用 GitHub 最新稳定发布；安装时校验 GitHub Releases API 提供的 SHA-256 digest，但尚未实现版本固定或独立签名验证；
- 正式 release-ready 仍需干净 Debian 13 虚拟机端到端验收。
