from __future__ import annotations

import getpass
import ipaddress
import json
import os
import re
import subprocess
from pathlib import Path

from .config import DEFAULTS, load_secrets, validate


def command_output(cmd: list[str]) -> str:
    try:
        result = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=8)
        return result.stdout if result.returncode == 0 else ""
    except Exception:
        return ""


def detect_network_defaults() -> dict:
    try:
        routes = json.loads(command_output(["ip", "-j", "route", "show", "default"]) or "[]")
        route = next((item for item in routes if item.get("dev")), None)
        if not route:
            return {}
        interface = route["dev"]
        detected = {"interface": interface}
        if route.get("gateway"):
            detected["upstream_gateway"] = route["gateway"]
        addresses = json.loads(command_output(["ip", "-j", "addr", "show", "dev", interface]) or "[]")
        infos = addresses[0].get("addr_info", []) if addresses else []
        info = next((item for item in infos if item.get("family") == "inet" and item.get("scope") == "global"), None)
        if info:
            detected["router_ipv4"] = info["local"]
            detected["lan_cidr"] = str(ipaddress.ip_network(f"{info['local']}/{info['prefixlen']}", strict=False))
        return detected
    except (ValueError, KeyError, TypeError, json.JSONDecodeError):
        return {}


def detect_networkmanager_connection(interface: str) -> str:
    raw = command_output(["nmcli", "-t", "-f", "NAME,DEVICE", "connection", "show", "--active"])
    for line in raw.splitlines():
        if not line or ":" not in line:
            continue
        name, device = line.rsplit(":", 1)
        if device == interface:
            return name.replace("\\:", ":")
    return ""


def detect_ssh_port() -> int:
    raw = command_output(["ss", "-ltnp"])
    matches = re.findall(r":(\d+)\s+[^\n]*\bsshd\b", raw)
    return int(matches[0]) if matches else 22


def ask(prompt: str, default: str | None = None, required: bool = True) -> str:
    suffix = f" [{default}]" if default not in {None, ""} else ""
    value = input(f"{prompt}{suffix}: ").strip()
    value = value or (default or "")
    if required and not value:
        raise ValueError(f"{prompt}不能为空")
    return value


def ask_bool(prompt: str, default: bool = True) -> bool:
    hint = "Y/n" if default else "y/N"
    while True:
        value = input(f"{prompt} [{hint}]: ").strip().lower()
        if not value:
            return default
        if value in {"y", "yes", "是"}:
            return True
        if value in {"n", "no", "否"}:
            return False
        print(f"输入无效：{prompt}只接受 y 或 n")


def ask_int(prompt: str, default: int, minimum: int = 1, maximum: int = 65535) -> int:
    value = int(ask(prompt, str(default)))
    if not minimum <= value <= maximum:
        raise ValueError(f"{prompt}必须位于 {minimum}-{maximum}")
    return value


def ask_list(prompt: str, default: list[str]) -> list[str]:
    value = ask(prompt, ",".join(default))
    return [item.strip() for item in value.split(",") if item.strip()]


def ask_validated(prompt: str, default: str, validator) -> str:
    while True:
        value = ask(prompt, default)
        try:
            validator(value)
            return value
        except ValueError as exc:
            print(f"输入无效：{exc}")


def collect_answers(detected: dict | None = None) -> tuple[dict, dict]:
    detected = detected or {}
    config = dict(DEFAULTS)
    interface = ask_validated("LAN 网络接口", detected.get("interface", config["interface"]),
                              lambda value: None if re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", value) else (_ for _ in ()).throw(ValueError("接口名称格式错误")))
    lan_cidr = ask_validated("LAN 网段 CIDR", detected.get("lan_cidr", config["lan_cidr"]),
                             lambda value: ipaddress.ip_network(value, strict=False))
    router_ipv4 = ask_validated("旁路由本机 IPv4", detected.get("router_ipv4", config["router_ipv4"]),
                                ipaddress.ip_address)
    gateway = ask_validated("上游主路由/网关 IPv4", detected.get("upstream_gateway", config["upstream_gateway"]),
                            ipaddress.ip_address)
    manage_network = ask_bool("由安装脚本配置本机静态 IPv4（NetworkManager）", False)
    web_bind = ask("Web 控制台监听地址", config["web_bind"])
    web_port = ask_int("Web 控制台端口", config["web_port"])
    ssh_port = ask_int("当前 sshd 实际监听端口（仅用于防火墙放行）", detect_ssh_port())
    tailscale = ask_bool("允许 Tailscale 网段访问 Web 控制台", config["enable_tailscale_access"])
    domestic_doh = ask_list("国内加密 DNS（逗号分隔）", config["domestic_doh"])
    global_doh = ask_list("全球加密 DNS（逗号分隔，经代理）", config["global_doh"])
    health_url = ask("代理健康检查 URL", config["proxy_health_url"])
    failure_threshold = ask_int("Watchdog 连续失败修复阈值", config["watchdog_failure_threshold"], 2, 20)
    cooldown = ask_int("Watchdog 修复冷却秒数", config["watchdog_cooldown_seconds"], 60, 86400)
    subscription_url = ask("Mihomo 订阅 HTTPS URL")
    password = getpass.getpass("Web 管理密码（至少 12 个字符）: ")
    confirmation = getpass.getpass("再次输入 Web 管理密码: ")
    if password != confirmation:
        raise ValueError("两次输入的密码不一致")

    connection = detect_networkmanager_connection(interface) if manage_network else ""
    if manage_network and not connection:
        raise ValueError("未检测到该接口的 NetworkManager 连接；请先用 nmcli 管理此接口，或在向导中选择不修改本机网络")
    config.update({
        "interface": interface,
        "lan_cidr": lan_cidr,
        "router_ipv4": router_ipv4,
        "upstream_gateway": gateway,
        "manage_network": manage_network,
        "network_connection": connection,
        "web_bind": web_bind,
        "web_port": web_port,
        "ssh_port": ssh_port,
        "enable_tailscale_access": tailscale,
        "domestic_doh": domestic_doh,
        "global_doh": global_doh,
        "proxy_health_url": health_url,
        "watchdog_failure_threshold": failure_threshold,
        "watchdog_cooldown_seconds": cooldown,
        "install_dependencies": True,
        "install_mihomo": True,
        "install_mosdns": True,
        "install_adguardhome": True,
    })
    secrets = {"subscription_url": subscription_url, "web_admin_password": password}
    validate(config)
    tmp = Path(os.devnull)
    if not subscription_url.startswith("https://"):
        raise ValueError("订阅地址只允许 HTTPS")
    if len(password) < 12:
        raise ValueError("Web 管理密码至少需要 12 个字符")
    return config, secrets


def networkmanager_commands(config: dict) -> list[list[str]]:
    connection = str(config.get("network_connection", "")).strip()
    if not connection:
        raise ValueError("未检测到 NetworkManager 连接名称，请关闭自动配置网络或手动填写")
    prefix = ipaddress.ip_network(config["lan_cidr"], strict=False).prefixlen
    return [
        [
            "nmcli", "connection", "modify", connection,
            "ipv4.method", "manual",
            "ipv4.addresses", f"{config['router_ipv4']}/{prefix}",
            "ipv4.gateway", config["upstream_gateway"],
            "ipv4.dns", config["router_ipv4"],
            "ipv4.ignore-auto-dns", "yes",
        ],
        ["nmcli", "connection", "up", connection],
    ]


def write_answers(config: dict, secrets: dict, config_path: Path, secrets_path: Path) -> None:
    config_path.parent.mkdir(parents=True, exist_ok=True)
    secrets_path.parent.mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(config, ensure_ascii=False, indent=2) + "\n")
    secrets_path.write_text(json.dumps(secrets, ensure_ascii=False, indent=2) + "\n")
    os.chmod(config_path, 0o600)
    os.chmod(secrets_path, 0o600)


def summarize(config: dict) -> str:
    return "\n".join([
        "\n部署参数确认：",
        f"  LAN 接口：{config['interface']}",
        f"  LAN 网段：{config['lan_cidr']}",
        f"  本机地址：{config['router_ipv4']}",
        f"  上游网关：{config['upstream_gateway']}",
        f"  配置静态地址：{'是' if config['manage_network'] else '否'}",
        f"  Web 控制台：http://{config['router_ipv4']}:{config['web_port']}",
        f"  Tailscale 管理访问：{'允许' if config['enable_tailscale_access'] else '关闭'}",
        "  DNS：国内加密直连；全球加密上游经代理；无公网明文 53 回退",
    ])


def run_wizard(config_path: str, secrets_path: str, install: bool, yes: bool,
               prefix: str = "/", bootstrap: bool = False) -> tuple[Path, Path]:
    detected = detect_network_defaults()
    config, secrets = collect_answers(detected)
    print(summarize(config))
    if not yes and not ask_bool("确认保存以上参数", True):
        raise SystemExit("已取消")
    config_file = Path(config_path)
    secrets_file = Path(secrets_path)
    write_answers(config, secrets, config_file, secrets_file)
    print(f"配置已写入 {config_file}；秘密已写入 {secrets_file}（0600）")
    if install:
        if not yes and not ask_bool("确认开始写入系统并部署旁路由", False):
            print("已生成配置，未执行安装")
            return config_file, secrets_file
        if Path(prefix).resolve() == Path("/") and os.geteuid() != 0:
            raise SystemExit("生产部署必须使用 root 权限运行")
        from .bootstrap import apply_networkmanager, install_bootstrap_binaries
        if bootstrap:
            install_bootstrap_binaries(config)
        from .cli import apply
        apply(str(config_file), str(secrets_file), prefix, True, "install")
        if Path(prefix).resolve() == Path("/") and config.get("manage_network"):
            print("即将切换本机静态 IP；SSH 连接可能中断，请使用新地址重新连接。")
            apply_networkmanager(config)
    return config_file, secrets_file
