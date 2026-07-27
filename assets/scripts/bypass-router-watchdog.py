#!/usr/bin/env python3
"""Self-healing watchdog for the local Debian bypass router.

Healthy runs are silent.  A message is printed only when a repair was made or
when the router remains unhealthy after repair attempts, making stdout suitable
for Hermes cron delivery.
"""
from __future__ import annotations

import fcntl
import json
import os
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

LOCK = Path("/run/bypass-router-watchdog/lock")
STATE = Path("/var/lib/bypass-router-watchdog/state.json")
LOG = Path("/var/log/bypass-router/watchdog.log")
SERVICES = ["mihomo", "mosdns", "adguardhome", "bypass-router-input-guard"]
GOOGLE_REPAIR_THRESHOLD = int(os.environ.get("WATCHDOG_FAILURE_THRESHOLD", "3"))
REPAIR_COOLDOWN_SECONDS = int(os.environ.get("WATCHDOG_COOLDOWN_SECONDS", "900"))


def run(argv: list[str], timeout: int = 15) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(argv, text=True, stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        return subprocess.CompletedProcess(argv, 124, (exc.stdout or "") + " timeout")
    except Exception as exc:
        return subprocess.CompletedProcess(argv, 125, str(exc))


def ok(argv: list[str], timeout: int = 15) -> bool:
    return run(argv, timeout).returncode == 0


def log(message: str) -> None:
    LOG.parent.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().astimezone().isoformat(timespec="seconds")
    with LOG.open("a") as f:
        f.write(f"{stamp} {message}\n")


def active(service: str) -> bool:
    return ok(["systemctl", "is-active", "--quiet", service])


def restart(service: str, actions: list[str]) -> bool:
    p = run(["systemctl", "restart", service], 35)
    time.sleep(1)
    good = p.returncode == 0 and active(service)
    actions.append(f"重启 {service}: {'成功' if good else '失败'}")
    log(actions[-1])
    return good


def dns_answer(name: str, qtype: str = "A", port: int = 53,
               attempts: int = 2) -> bool:
    for attempt in range(attempts):
        p = run(["dig", "+time=4", "+tries=1", "+short", "@127.0.0.1",
                 "-p", str(port), name, qtype], 7)
        if p.returncode == 0 and bool(p.stdout.strip()):
            return True
        if attempt + 1 < attempts:
            time.sleep(2)
    return False


def dns_empty_aaaa(name: str) -> bool:
    for attempt in range(2):
        p = run(["dig", "+time=4", "+tries=1", "+short", "@127.0.0.1",
                 name, "AAAA"], 7)
        if p.returncode == 0 and not p.stdout.strip():
            return True
        if attempt == 0:
            time.sleep(2)
    return False


def google_proxy() -> bool:
    return ok(["curl", "-4", "-x", "http://127.0.0.1:7890", "-sS",
               "--max-time", "10", "-o", "/dev/null", "https://www.google.com"], 13)


def privacy_dns_config() -> bool:
    """Strict mode: no configured public plain-DNS upstream or silent fallback."""
    try:
        import yaml
        mos = yaml.safe_load(Path("/etc/bypass-router/mosdns/config.yaml").read_text()) or {}
        forwards = [p for p in (mos.get("plugins") or []) if p.get("type") == "forward"]
        upstreams = [u for p in forwards for u in ((p.get("args") or {}).get("upstreams") or [])]
        if not upstreams or not all(str(u.get("addr", "")).startswith(("https://", "tls://")) for u in upstreams):
            return False
        ag = yaml.safe_load(Path("/etc/bypass-router/adguardhome/AdGuardHome.yaml").read_text())["dns"]
        return ag.get("upstream_dns") == ["127.0.0.1:5335"] and not ag.get("fallback_dns")
    except Exception:
        return False


def direct_network() -> bool:
    # Use a domestic endpoint because foreign/example domains can transiently
    # fail in the policy DNS path without the physical uplink being broken.
    route = ok(["ip", "route", "get", "223.5.5.5"], 3)
    web = ok(["curl", "-4", "-sS", "--max-time", "8", "-o", "/dev/null",
              "https://www.baidu.com"], 11)
    return route and web


def tproxy_enabled() -> bool:
    return ok(["systemctl", "is-enabled", "--quiet", "bypass-router-tproxy.service"], 4)


def tproxy_healthy() -> bool:
    if not active("bypass-router-tproxy.service"):
        return False
    checks = [
        ["nft", "list", "table", "inet", "bypass_router"],
        ["sh", "-c", "ip -4 rule show priority 100 | grep -q 'fwmark 0x1/0x1 lookup 100'"],
        ["sh", "-c", "ip -4 route show table 100 | grep -q '^local default dev lo'"],
        ["sh", "-c", "ss -H -lnt | grep -qE '(^|[[:space:]])([^[:space:]]*:)?7892([[:space:]]|$)'"],
        ["sh", "-c", "ss -H -lnu | grep -qE '(^|[[:space:]])([^[:space:]]*:)?7893([[:space:]]|$)'"],
    ]
    return all(ok(x, 5) for x in checks)



def assess() -> list[str]:
    faults: list[str] = []
    for service in SERVICES:
        if not active(service):
            faults.append(f"{service} 未运行")
    if not direct_network():
        faults.append("本机 IPv4 直连失败")
    if not dns_answer("baidu.com"):
        faults.append("国内 DNS A 失败")
    if not dns_answer("ipv6.baidu.com", "AAAA"):
        faults.append("国内 DNS AAAA 失败")
    if not dns_answer("google.com"):
        faults.append("Google DNS A 失败")
    if not dns_empty_aaaa("google.com"):
        faults.append("Google AAAA 未被抑制")
    if not privacy_dns_config():
        faults.append("严格隐私 DNS 配置被破坏")
    if not google_proxy():
        faults.append("Google 代理访问失败")
    if tproxy_enabled() and not tproxy_healthy():
        faults.append("透明代理规则/策略路由不完整")
    if not active("tailscaled"):
        faults.append("Tailscale 未运行")
    return faults


def repair(initial: list[str]) -> list[str]:
    actions: list[str] = []

    # Repair the physical/default network only when ordinary direct networking
    # is broken.  A Google-only failure must never bounce NetworkManager.
    if "本机 IPv4 直连失败" in initial:
        restart("NetworkManager", actions)
        time.sleep(3)

    if not active("tailscaled"):
        restart("tailscaled", actions)

    # Dependency order: proxy DNS -> policy DNS -> LAN DNS frontend.
    if not active("mihomo") or "Google 代理访问失败" in initial or "Google DNS A 失败" in initial:
        restart("mihomo", actions)
        time.sleep(3)
    if not active("mosdns") or any("DNS" in x for x in initial):
        restart("mosdns", actions)
        time.sleep(2)
    if not active("adguardhome") or any("DNS" in x for x in initial):
        restart("adguardhome", actions)
        time.sleep(4)

    if not active("bypass-router-input-guard"):
        restart("bypass-router-input-guard", actions)

    if tproxy_enabled() and not tproxy_healthy():
        restart("bypass-router-tproxy", actions)

    return actions


def load_state() -> dict:
    try:
        return json.loads(STATE.read_text())
    except Exception:
        return {}


def save_state(healthy: bool, faults: list[str], actions: list[str], *, repaired: bool = False) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    previous = load_state()
    failures = 0 if healthy else int(previous.get("consecutive_failures", 0)) + 1
    data = {
        "checked_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "healthy": healthy,
        "consecutive_failures": failures,
        "faults": faults,
        "actions": actions,
        "last_repair_at": (datetime.now().astimezone().isoformat(timespec="seconds")
                           if repaired else previous.get("last_repair_at")),
    }
    tmp = STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2) + "\n")
    os.replace(tmp, STATE)


def main() -> int:
    LOCK.parent.mkdir(parents=True, exist_ok=True)
    with LOCK.open("w") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return 0

        initial = assess()
        if not initial:
            save_state(True, [], [])
            return 0

        previous = load_state()
        next_failures = int(previous.get("consecutive_failures", 0)) + 1
        only_google = initial == ["Google 代理访问失败"]
        if only_google and next_failures < GOOGLE_REPAIR_THRESHOLD:
            save_state(False, initial, [])
            return 0

        if only_google and previous.get("last_repair_at"):
            try:
                last = datetime.fromisoformat(previous["last_repair_at"])
                if (datetime.now().astimezone() - last).total_seconds() < REPAIR_COOLDOWN_SECONDS:
                    save_state(False, initial, [])
                    return 0
            except (TypeError, ValueError):
                pass

        log("发现故障: " + "；".join(initial))
        actions = repair(initial)
        # Mihomo DNS may need several seconds after a restart to initialize
        # providers and complete its first upstream health selection.
        time.sleep(10)
        remaining = assess()
        healthy = not remaining
        save_state(healthy, remaining, actions, repaired=bool(actions))

        if healthy:
            print("✅ 旁路由自动修复完成\n"
                  f"发现：{'；'.join(initial)}\n"
                  f"操作：{'；'.join(actions) if actions else '重新检测后已恢复'}")
            return 0

        print("🚨 旁路由自动修复未完全成功\n"
              f"最初：{'；'.join(initial)}\n"
              f"操作：{'；'.join(actions) if actions else '无可执行修复'}\n"
              f"仍有：{'；'.join(remaining)}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
