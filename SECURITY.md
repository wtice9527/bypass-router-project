# 安全策略

## 禁止提交

- 订阅URL和Token；
- 节点UUID、密码、私钥、公钥参数；
- Web登录密码、Cookie和会话密钥；
- Tailscale密钥；
- 真实家庭公网IP和机器身份文件。

## 报告漏洞

请使用 GitHub 仓库的 **Security → Report a vulnerability** 私下报告能够导致远程命令执行、认证绕过、DNS 明文泄漏、任意 systemd 操作、任意路径读写或防火墙绕过的问题。不要在公开 Issue 中提交漏洞细节、订阅 URL、Token、节点凭据或生产日志。

当前维护分支为 `main`；安全修复优先支持最新发布版本。

## 默认防护

- 控制接口仅回环监听；
- Web操作使用固定白名单；
- CSRF与SameSite会话；
- 配置候选先校验；
- 失败自动回滚；
- 严格DNS失败关闭。
