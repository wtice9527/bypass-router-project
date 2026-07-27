# 贡献指南

## 开发环境

```bash
make setup
make test
make validate
make scan
```

提交前必须确保：

- `pytest` 全部通过；
- nftables、Python 和 JavaScript 静态校验通过；
- `scripts/scan-secrets.py` 无命中；
- 不提交 `config.json`、`secrets.json`、订阅 URL、节点凭据或真实机器身份；
- 网络行为变化附带对应测试和回滚说明。

## 提交格式

```text
type: concise description
```

常用类型：`feat`、`fix`、`docs`、`test`、`refactor`、`chore`。

## 安全问题

不要在公开 Issue 中提交订阅 URL、Token、密码、节点配置或客户端流量记录。安全问题请按照 `SECURITY.md` 处理。
