from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path

DEFAULTS = {
    "interface": "eth0",
    "router_ipv4": "192.168.50.2",
    "lan_cidr": "192.168.50.0/24",
    "upstream_gateway": "192.168.50.1",
    "web_bind": "0.0.0.0",
    "web_port": 8443,
    "mihomo_mixed_port": 7890,
    "mihomo_redir_port": 7892,
    "mihomo_tproxy_port": 7893,
    "mihomo_dns_port": 1053,
    "mihomo_controller_port": 9090,
    "mosdns_port": 5335,
    "adguard_web_port": 3000,
    "fwmark": "0x1/0x1",
    "fwmark_value": "0x1",
    "route_table": 100,
    "route_priority": 100,
    "strict_dns": True,
    "domestic_doh": ["https://dns.alidns.com/dns-query", "https://doh.pub/dns-query"],
    "global_doh": ["https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query"],
    "proxy_health_url": "https://www.google.com/generate_204",
    "watchdog_failure_threshold": 3,
    "watchdog_cooldown_seconds": 900,
    "enable_tailscale_access": True,
}

SECRET_KEYS = {"subscription_url", "web_admin_password"}


def load(path: str | Path) -> dict:
    supplied = json.loads(Path(path).read_text())
    unknown = set(supplied) - set(DEFAULTS)
    if unknown:
        raise ValueError("存在未知配置参数: " + ", ".join(sorted(unknown)))
    forbidden = set(supplied) & SECRET_KEYS
    if forbidden:
        raise ValueError("秘密参数不得写入 config.json")
    data = dict(DEFAULTS)
    data.update(supplied)
    validate(data)
    return data


def load_secrets(path: str | Path | None, required: bool = False) -> dict:
    if path is None:
        if required:
            raise ValueError("安装需要 secrets.json")
        return {}
    p = Path(path)
    if not p.exists():
        if required:
            raise ValueError("secrets.json 不存在")
        return {}
    data = json.loads(p.read_text())
    unknown = set(data) - SECRET_KEYS
    if unknown:
        raise ValueError("存在未知秘密参数: " + ", ".join(sorted(unknown)))
    if required:
        for key in SECRET_KEYS:
            value = str(data.get(key, ""))
            if not value or value.startswith("CHANGE_ME"):
                raise ValueError(f"秘密参数 {key} 未设置")
    if data.get("subscription_url") and not str(data["subscription_url"]).startswith("https://"):
        raise ValueError("订阅地址只允许 HTTPS")
    if data.get("web_admin_password") and len(str(data["web_admin_password"])) < 12:
        raise ValueError("Web 管理密码至少需要 12 个字符")
    return data


def validate(c: dict) -> None:
    net = ipaddress.ip_network(c["lan_cidr"], strict=False)
    if net.version != 4:
        raise ValueError("当前版本只支持 IPv4 LAN")
    router = ipaddress.ip_address(c["router_ipv4"])
    gateway = ipaddress.ip_address(c["upstream_gateway"])
    if router not in net or gateway not in net:
        raise ValueError("旁路由地址和上游网关必须位于 LAN 网段")
    if router == gateway or router in {net.network_address, net.broadcast_address}:
        raise ValueError("旁路由地址无效或与上游网关冲突")
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", str(c["interface"])):
        raise ValueError("网络接口名称无效")
    try:
        bind = ipaddress.ip_address(c["web_bind"])
        if bind.version != 4:
            raise ValueError
    except ValueError as exc:
        raise ValueError("Web 绑定地址必须是 IPv4 地址") from exc
    port_keys = (
        "web_port", "mihomo_mixed_port", "mihomo_redir_port",
        "mihomo_tproxy_port", "mihomo_dns_port", "mihomo_controller_port",
        "mosdns_port", "adguard_web_port",
    )
    ports = [int(c[k]) for k in port_keys]
    if len(set(ports)) != len(ports) or any(not 1 <= p <= 65535 for p in ports):
        raise ValueError("端口必须有效且互不冲突")
    if c.get("strict_dns") is not True:
        raise ValueError("本项目要求 strict_dns=true")
    for group in ("domestic_doh", "global_doh"):
        values = c.get(group)
        if not isinstance(values, list) or not values:
            raise ValueError(f"{group} 不能为空")
        if not all(str(x).startswith(("https://", "tls://")) for x in values):
            raise ValueError(f"{group} 只能包含 DoH/DoT")
    if int(c["watchdog_failure_threshold"]) < 2:
        raise ValueError("Watchdog 连续失败阈值至少为 2")
    if int(c["watchdog_cooldown_seconds"]) < 60:
        raise ValueError("Watchdog 冷却时间至少为 60 秒")
    if not re.fullmatch(r"0x[0-9a-fA-F]+", str(c["fwmark_value"])):
        raise ValueError("fwmark_value 必须是十六进制整数")
    if int(str(c["fwmark_value"]), 16) == 0:
        raise ValueError("fwmark_value 不能为 0")
    if not re.fullmatch(r"0x[0-9a-fA-F]+/0x[0-9a-fA-F]+", str(c["fwmark"])):
        raise ValueError("fwmark 必须包含十六进制值和掩码")
    if not str(c["fwmark"]).startswith(str(c["fwmark_value"]) + "/"):
        raise ValueError("fwmark 与 fwmark_value 不一致")
    if not 1 <= int(c["route_table"]) <= 252:
        raise ValueError("策略路由表必须在 1 到 252 之间")
    if not 1 <= int(c["route_priority"]) <= 32765:
        raise ValueError("策略路由优先级无效")


def public(c: dict) -> dict:
    return {k: v for k, v in c.items() if k not in SECRET_KEYS}


def template_values(c: dict) -> dict[str, str]:
    values: dict[str, str] = {}
    for key, value in c.items():
        upper = key.upper()
        if isinstance(value, bool):
            values[upper] = str(value).lower()
        elif isinstance(value, list):
            values[upper] = "\n".join(f"        - addr: {item}" for item in value)
        else:
            values[upper] = str(value)
    return values


def render(text: str, c: dict) -> str:
    values = template_values(c)
    text = re.sub(r"{{([A-Z0-9_]+)}}", lambda match: values.get(match.group(1), match.group(0)), text)
    unresolved = re.findall(r"{{([A-Z0-9_]+)}}", text)
    if unresolved:
        raise ValueError("模板存在未解析变量: " + unresolved[0])
    return text


def render_tree(template_root: Path, output_root: Path, c: dict) -> list[Path]:
    written: list[Path] = []
    for src in template_root.rglob("*"):
        if not src.is_file():
            continue
        rel = src.relative_to(template_root)
        if rel.name.endswith(".tmpl"):
            rel = rel.with_name(rel.name[:-5])
        dst = output_root / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        dst.write_text(render(src.read_text(), c))
        written.append(dst)
    return written
