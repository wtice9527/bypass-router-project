# 发布验收

## 本地门禁

```bash
python3 scripts/scan-secrets.py
python3 -m pytest -q
routerctl validate -c config.example.json
routerctl generate -c config.example.json -o build/rootfs
```

要求全部返回 0，生成目录不得包含 `{{...}}` 或 secrets 真值。

## 隔离生命周期

```bash
cp secrets.example.json /tmp/router-secrets.json
python3 - <<'PY'
import json
p='/tmp/router-secrets.json'
d=json.load(open(p))
d['subscription_url']='https://example.com/subscription'
d['web_admin_password']='Example-Only-Password-2026!'
open(p,'w').write(json.dumps(d))
PY
T=$(mktemp -d)
routerctl install -c config.example.json -s /tmp/router-secrets.json --prefix "$T" --yes
routerctl status --prefix "$T"
routerctl upgrade -c config.example.json -s /tmp/router-secrets.json --prefix "$T" --yes
routerctl rollback --prefix "$T" --yes
routerctl uninstall --prefix "$T" --yes
```

## 干净 Debian 13 虚拟机

必须逐项通过：

1. 安装前保存控制台和原网络配置；
2. 安装后重启，六个核心服务及两个 timer 正常；
3. 国内站点连续 20 次成功；
4. Google 代理连续 20 次成功，无偶发超时；
5. LAN 客户端 DNS/TCP/UDP 真正经过旁路由；
6. 国内域名获得国内 CDN，国外 DNS 经代理 DoH；
7. 停止加密 DNS 上游时返回失败，不回退公网明文 53；
8. 常用节点健康时保持，故障后切备用，恢复后切回；
9. 所有代理失效时按配置回退 DIRECT；
10. 订阅刷新后 preferred 节点仍位于 Provider 第一位；
11. Web 登录、CSRF、节点切换、订阅、规则、AdGuard、服务和回滚可用；
12. 故意安装坏配置会自动恢复旧版本；
13. 卸载只删除 manifest 文件，网络和管理路径恢复；
14. 发布包敏感信息扫描通过。

未完成虚拟机整套验收前，状态只能写“项目已实现并通过本地/隔离验证”，不能写“release-ready”。
