# 架构

## 组件

```text
客户端 → AdGuard Home → MosDNS → Mihomo → 加密 DoH
客户端 TCP → nft Redirect → Mihomo redir-port
客户端 UDP → nft TProxy → mark + table 100 → Mihomo tproxy-port
```

## 配置层

`config.json` 是唯一非敏感机器参数来源。`routerctl generate` 将其渲染为服务配置。订阅和密码在首次配置时单独写入 secrets，不进入项目仓库或生成报告。

## 生命周期

```text
检查环境 → 生成候选配置 → 语法校验 → 备份 → 安装 → 启动 → 端到端验证
```

升级与回滚使用相同事务模型。

## 透明代理

只接管从指定 LAN 接口进入、来源属于 LAN 网段且实际以本机为网关的 IPv4 流量。私网、组播和保留地址直连。TCP 使用 Redirect，UDP 使用 TProxy。

## DNS隐私

公网解析仅允许代理后的 HTTPS DNS。上游不可用时返回失败，不回退到公网 UDP/TCP 53。LAN 客户端到本机的 53 属于局域网内部路径，可保留。
