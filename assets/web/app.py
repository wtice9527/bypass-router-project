#!/usr/bin/env python3
from __future__ import annotations

import hmac
import ipaddress
import json
import os
import re
import secrets
import tempfile
import threading
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from functools import wraps
from pathlib import Path
from urllib.parse import urlparse

from flask import Flask, Response, jsonify, request, send_from_directory, session
from werkzeug.security import check_password_hash, generate_password_hash

APP_DIR = Path(os.environ.get("BYPASS_ROUTER_WEB_DIR", "/opt/bypass-router-web"))
STATE = Path(os.environ.get("BYPASS_ROUTER_WATCHDOG_STATE", "/var/lib/bypass-router-watchdog/state.json"))
PASSWORD_FILE = Path(os.environ.get("BYPASS_ROUTER_PASSWORD_FILE", "/etc/bypass-router-web/password"))
PASSWORD_HASH_FILE = Path(os.environ.get("BYPASS_ROUTER_PASSWORD_HASH_FILE", "/etc/bypass-router-web/password.hash"))
AUTH_GENERATION_FILE = Path(os.environ.get("BYPASS_ROUTER_AUTH_GENERATION_FILE", "/etc/bypass-router-web/auth-generation"))
SECRET_FILE = Path(os.environ.get("BYPASS_ROUTER_SECRET_FILE", "/etc/bypass-router-web/secret-key"))
WATCHDOG = os.environ.get("BYPASS_ROUTER_WATCHDOG", "/usr/local/sbin/bypass-router-watchdog")
SERVICES = [
    "mihomo", "mosdns", "adguardhome", "bypass-router-tproxy",
    "bypass-router-input-guard", "NetworkManager",
]
ALLOWED_ACTIONS = {
    "repair": [WATCHDOG],
    "restart_dns": ["systemctl", "restart", "mosdns", "adguardhome"],
    "restart_proxy": ["systemctl", "restart", "mihomo", "bypass-router-tproxy"],
    "restart_tproxy": ["systemctl", "restart", "bypass-router-tproxy"],
}
MANAGED_SERVICES = set(SERVICES + ["bypass-router-web"])
SERVICE_VERBS = {"start", "stop", "restart"}
MIHOMO_API = os.environ.get("MIHOMO_API", "http://127.0.0.1:9090")
ADGUARD_API = os.environ.get("ADGUARD_API", "http://127.0.0.1:3000")
AUDIT_LOG = Path(os.environ.get("BYPASS_ROUTER_AUDIT_LOG", "/var/log/bypass-router/web-audit.jsonl"))
SAFE_SERVICE_VERBS = {"mihomo":{"restart"},"mosdns":{"restart"},"adguardhome":{"restart"},"bypass-router-tproxy":{"start","stop","restart"}}

app = Flask(__name__, static_folder=None)
app.secret_key = SECRET_FILE.read_text().strip()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Strict",
    PERMANENT_SESSION_LIFETIME=3600,
)


def run(cmd: list[str], timeout: int = 15) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=timeout)
        return p.returncode, p.stdout.strip()
    except subprocess.TimeoutExpired:
        return 124, "timeout"
    except Exception as exc:
        return 125, str(exc)


def json_http(url: str, method: str = "GET", payload=None, timeout: int = 15):
    body = None if payload is None else json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body, method=method)
    if body is not None: req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            if not raw:
                return resp.status, {}
            try:
                return resp.status, json.loads(raw)
            except json.JSONDecodeError:
                return resp.status, {"text": raw.decode(errors="replace")}
    except urllib.error.HTTPError as exc:
        return exc.code, {"error": exc.read().decode(errors="replace") or str(exc)}
    except Exception as exc: return 599, {"error": str(exc)}


def mihomo_groups() -> dict:
    code, data = json_http(MIHOMO_API + "/proxies", timeout=8)
    if code != 200:
        return {"groups": [], "error": data.get("error", "controller unavailable")}
    proxies = data.get("proxies", {})
    pcode, provider = json_http(MIHOMO_API + "/providers/proxies/main", timeout=8)
    provider_nodes = {n.get("name"): n for n in provider.get("proxies", [])} if pcode == 200 else {}
    groups = []
    group_types = {"Selector", "URLTest", "Fallback", "LoadBalance"}
    for name, value in proxies.items():
        if value.get("type") not in group_types:
            continue
        nodes = []
        for node_name in value.get("all", []):
            node = proxies.get(node_name, {})
            pnode = provider_nodes.get(node_name, {})
            history = pnode.get("history") or node.get("history") or []
            delay = history[-1].get("delay") if history else None
            nodes.append({
                "name": node_name,
                "type": node.get("type") or pnode.get("type") or "Proxy",
                "delay": delay,
                "alive": pnode.get("alive", node.get("alive", True)),
                "udp": node.get("udp", pnode.get("udp", False)),
                "xudp": node.get("xudp", pnode.get("xudp", False)),
                "provider": node.get("provider-name") or pnode.get("provider-name") or "",
            })
        available = sum(1 for n in nodes if n["alive"] is not False)
        current = value.get("now", "")
        current_node = proxies.get(current, {})
        current_history = current_node.get("history") or []
        current_delay = current_history[-1].get("delay") if current_history else next((n["delay"] for n in nodes if n["name"] == current), None)
        groups.append({
            "name": name, "type": value.get("type"), "now": current,
            "nodes": nodes, "selectable": value.get("type") in {"Selector", "URLTest", "Fallback", "LoadBalance"},
            "available": available, "total": len(nodes), "current_delay": current_delay,
            "udp": value.get("udp", False), "alive": value.get("alive", True),
        })
    return {"groups": groups}


def adguard_summary() -> dict:
    code,status=json_http(ADGUARD_API+"/control/status",timeout=6)
    if code != 200: return {"available":False,"error":status.get("error","unavailable")}
    c2,stats=json_http(ADGUARD_API+"/control/stats",timeout=8); c3,filt=json_http(ADGUARD_API+"/control/filtering/status",timeout=8)
    s=stats if c2==200 else {}; f=filt if c3==200 else {}
    return {"available":True,"running":status.get("running",False),"protection_enabled":status.get("protection_enabled",False),"dns_port":status.get("dns_port"),"num_dns_queries":s.get("num_dns_queries",0),"num_blocked_filtering":s.get("num_blocked_filtering",0),"avg_processing_time":s.get("avg_processing_time",0),"filters":len(f.get("filters") or []),"user_rules":len(f.get("user_rules") or [])}


def audit(event: str, ok: bool, details: dict | None = None):
    entry={"timestamp":datetime.now().astimezone().isoformat(timespec="seconds"),"remote":request.remote_addr if request else "system","event":event,"ok":bool(ok),"details":details or {}}
    AUDIT_LOG.parent.mkdir(parents=True,exist_ok=True)
    with AUDIT_LOG.open("a") as f: f.write(json.dumps(entry,ensure_ascii=False)+"\n")


def provider_status() -> dict:
    code,data=json_http(MIHOMO_API+"/providers/proxies",timeout=8); p=data.get("providers",{}).get("main",{}) if code==200 else {}
    _,timer=run(["systemctl","show","mihomo-provider-update.timer","-p","ActiveState","-p","LastTriggerUSec","-p","UnitFileState"],6)
    vals=dict(line.split("=",1) for line in timer.splitlines() if "=" in line)
    return {"available":bool(p),"type":p.get("vehicleType"),"proxy_count":len(p.get("proxies",[])),"updated_at":p.get("updatedAt"),"timer_active":vals.get("ActiveState")=="active","timer_enabled":vals.get("UnitFileState")=="enabled","last_trigger":vals.get("LastTriggerUSec")}


def connections_summary() -> dict:
    code,data=json_http(MIHOMO_API+"/connections",timeout=6)
    return {"count":len(data.get("connections",[])) if code==200 else 0,"upload":data.get("uploadTotal",0) if code==200 else 0,"download":data.get("downloadTotal",0) if code==200 else 0}


def diagnostics() -> list[dict]:
    p_ok,_=privacy_config(); t=tproxy_state(); g_ok,g_code=google_ok(); checks=[]
    def add(name,ok,detail): checks.append({"name":name,"ok":bool(ok),"detail":detail})
    rc,out=run(["ip","route","get","223.5.5.5"],5); add("IPv4路由",rc==0,out.splitlines()[0] if out else "无路由")
    for svc in SERVICES:
        state=service_state(svc); add("服务 "+svc,state=="active",state)
    add("严格隐私DNS",p_ok,"全部不变量通过" if p_ok else "配置不符合严格模式")
    add("Google代理访问",g_ok,"HTTP "+g_code); add("TProxy规则与路由",t["healthy"],"客户端 "+t["client"])
    ps=provider_status(); add("节点Provider",ps["available"] and ps["proxy_count"]>0,f"{ps['proxy_count']} 个节点")
    ag=adguard_summary(); add("AdGuard过滤",ag.get("filters",0)>0,f"{ag.get('filters',0)} 个过滤器")
    return checks


def service_state(name: str) -> str:
    rc, out = run(["systemctl", "is-active", name], 4)
    return out if rc == 0 else (out or "inactive")


def dig(name: str, qtype: str = "A") -> list[str]:
    rc, out = run(["dig", "+time=3", "+tries=1", "+short", "@127.0.0.1", name, qtype], 6)
    return [x for x in out.splitlines() if x] if rc == 0 else []


def google_ok() -> tuple[bool, str]:
    rc, out = run(["curl", "-4", "-x", "http://127.0.0.1:7890", "-sS",
                   "--max-time", "8", "-o", "/dev/null", "-w", "%{http_code}",
                   "https://www.google.com"], 11)
    return rc == 0 and out.startswith(("2", "3")), out


def privacy_config() -> tuple[bool, dict]:
    import yaml
    mosdns = yaml.safe_load(Path("/etc/bypass-router/mosdns/config.yaml").read_text()) or {}
    plugins = mosdns.get("plugins") or []
    forwards = [p for p in plugins if p.get("type") == "forward"]
    upstreams = [u for p in forwards for u in ((p.get("args") or {}).get("upstreams") or [])]
    encrypted = bool(upstreams) and all(str(u.get("addr", "")).startswith(("https://", "tls://")) for u in upstreams)
    # 国内解析器允许用于国内域名的就近 CDN 定位，但传输必须是 DoH/DoT；
    # 旧检查把固定的 DoH dial_addr 误判成明文国内 DNS。
    domestic_encrypted = any(
        str(u.get("addr", "")).startswith(("https://dns.alidns.com/", "https://doh.pub/"))
        for u in upstreams
    )
    global_proxy = any((p.get("args") or {}).get("socks5") == "127.0.0.1:7890" for p in forwards)
    dns = yaml.safe_load(Path("/etc/bypass-router/adguardhome/AdGuardHome.yaml").read_text())["dns"]
    adguard_upstreams = dns.get("upstream_dns") or []
    no_fallback = not (dns.get("fallback_dns") or [])
    # AdGuard may repopulate default bootstrap addresses after restart. They
    # are not used when every upstream is a literal loopback address.
    bootstrap_not_needed = adguard_upstreams == ["127.0.0.1:5335"]
    data = {
        "encrypted_upstreams": encrypted,
        "domestic_encrypted": domestic_encrypted,
        "global_via_proxy": global_proxy,
        "adguard_no_fallback": no_fallback,
        "adguard_bootstrap_unused": bootstrap_not_needed,
    }
    return all(data.values()), data


def tproxy_state() -> dict:
    rc1, nft = run(["nft", "list", "table", "inet", "bypass_router"], 5)
    rc2, rule = run(["ip", "-4", "rule", "show", "priority", "100"], 5)
    rc3, route = run(["ip", "-4", "route", "show", "table", "100"], 5)
    tcp = re.search(r"counter packets (\d+) bytes (\d+) redirect to :7892", nft)
    udp = re.search(r"counter packets (\d+) bytes (\d+) accept", nft)
    return {
        "healthy": rc1 == rc2 == rc3 == 0 and "fwmark 0x1/0x1" in rule and "local default dev lo" in route,
        "client": os.environ.get("BYPASS_ROUTER_CLIENT_SCOPE", "所有使用本机作为 IPv4 网关的局域网设备"),
        "tcp_packets": int(tcp.group(1)) if tcp else 0,
        "udp_packets": int(udp.group(1)) if udp else 0,
    }


def system_metrics() -> dict:
    def first(path: str) -> str:
        try:
            return Path(path).read_text().strip()
        except Exception:
            return ""
    uptime = float(first("/proc/uptime").split()[0] or 0)
    mem = {}
    for line in first("/proc/meminfo").splitlines():
        k, v = line.split(":", 1)
        mem[k] = int(v.strip().split()[0])
    used = mem.get("MemTotal", 0) - mem.get("MemAvailable", 0)
    disk = os.statvfs("/")
    return {
        "uptime_seconds": int(uptime),
        "memory_used_percent": round(used / mem.get("MemTotal", 1) * 100, 1),
        "disk_used_percent": round((disk.f_blocks - disk.f_bavail) / disk.f_blocks * 100, 1),
    }


def load_watchdog() -> dict:
    try:
        return json.loads(STATE.read_text())
    except Exception:
        return {"healthy": False, "faults": ["暂无监控状态"]}


def auth_generation() -> str:
    try:
        return AUTH_GENERATION_FILE.read_text().strip()
    except Exception:
        return "1"


def verify_password(password: str) -> bool:
    try:
        if PASSWORD_HASH_FILE.exists():
            return check_password_hash(PASSWORD_HASH_FILE.read_text().strip(), password)
        return PASSWORD_FILE.exists() and hmac.compare_digest(password, PASSWORD_FILE.read_text().strip())
    except Exception:
        return False


def write_password_hash(password: str):
    value = generate_password_hash(password, method="scrypt") + "\n"
    fd, tmp = tempfile.mkstemp(prefix=".password.hash.", dir=str(PASSWORD_HASH_FILE.parent))
    os.close(fd)
    Path(tmp).write_text(value)
    os.chmod(tmp, 0o600)
    os.replace(tmp, PASSWORD_HASH_FILE)
    generation = str(int(time.time())) + "-" + secrets.token_hex(6)
    fd, tmp = tempfile.mkstemp(prefix=".auth-generation.", dir=str(AUTH_GENERATION_FILE.parent))
    os.close(fd)
    Path(tmp).write_text(generation + "\n")
    os.chmod(tmp, 0o600)
    os.replace(tmp, AUTH_GENERATION_FILE)
    PASSWORD_FILE.unlink(missing_ok=True)


def password_policy(password: str) -> str | None:
    if len(password) < 12:
        return "新密码至少需要12个字符"
    if len(password) > 256:
        return "新密码过长"
    classes = sum(bool(re.search(pattern, password)) for pattern in (r"[a-z]", r"[A-Z]", r"[0-9]", r"[^A-Za-z0-9]"))
    if classes < 3:
        return "新密码至少应包含大写字母、小写字母、数字、符号中的三类"
    return None


def allowed_remote(addr: str) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        lan = ipaddress.ip_network(os.environ.get("BYPASS_ROUTER_LAN_CIDR", "192.168.50.0/24"), strict=False)
        allow_tailscale = os.environ.get("BYPASS_ROUTER_ALLOW_TAILSCALE", "true").lower() == "true"
        return ip.is_loopback or ip in lan or (allow_tailscale and ip in ipaddress.ip_network("100.64.0.0/10"))
    except ValueError:
        return False


def require_auth(fn):
    @wraps(fn)
    def wrapped(*args, **kwargs):
        if not allowed_remote(request.remote_addr or ""):
            return jsonify(error="forbidden network"), 403
        if not session.get("authenticated"):
            return jsonify(error="authentication required"), 401
        if session.get("auth_generation") != auth_generation():
            session.clear()
            return jsonify(error="session expired"), 401
        return fn(*args, **kwargs)
    return wrapped


def require_csrf() -> bool:
    token = request.headers.get("X-CSRF-Token", "")
    return bool(token and hmac.compare_digest(token, session.get("csrf", "")))


@app.after_request
def security_headers(resp: Response):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Cache-Control"] = "no-store"
    if request.path.startswith("/adguard/") or request.path.startswith("/control/"):
        # The native AdGuard UI is embedded by this same-origin console.
        resp.headers["X-Frame-Options"] = "SAMEORIGIN"
        resp.headers["Content-Security-Policy"] = "frame-ancestors 'self'; default-src 'self' data: blob: 'unsafe-inline' 'unsafe-eval'; connect-src 'self'; img-src 'self' data: blob:"
    else:
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'"
    return resp


@app.get("/")
def index():
    resp = send_from_directory(APP_DIR / "static", "index.html")
    resp.headers["Cache-Control"] = "no-store, max-age=0"
    return resp


@app.get("/app.js")
def js():
    return send_from_directory(APP_DIR / "static", "app.js")


@app.get("/theme.css")
def theme_css():
    return send_from_directory(APP_DIR / "static", "theme.css")


@app.get("/healthz")
def healthz():
    return jsonify(ok=True)


@app.post("/api/login")
def login():
    if not allowed_remote(request.remote_addr or ""):
        return jsonify(error="forbidden network"), 403
    supplied = (request.get_json(silent=True) or {}).get("password", "")
    if not verify_password(supplied):
        time.sleep(0.5)
        return jsonify(error="密码错误"), 401
    session.clear()
    session.permanent = True
    session["authenticated"] = True
    session["auth_generation"] = auth_generation()
    session["csrf"] = secrets.token_urlsafe(24)
    return jsonify(ok=True, csrf=session["csrf"])


@app.post("/api/logout")
@require_auth
def logout():
    if not require_csrf():
        return jsonify(error="invalid csrf token"), 403
    session.clear()
    return jsonify(ok=True)


@app.get("/api/session")
def session_info():
    if not session.get("authenticated") or session.get("auth_generation") != auth_generation():
        session.clear()
        return jsonify(authenticated=False)
    return jsonify(authenticated=True, csrf=session.get("csrf"))


@app.post("/api/settings/password")
@require_auth
def change_password():
    if not require_csrf():
        return jsonify(error="invalid csrf token"), 403
    body = request.get_json(silent=True) or {}
    current = str(body.get("current_password", ""))
    new_password = str(body.get("new_password", ""))
    confirmation = str(body.get("confirm_password", ""))
    if not verify_password(current):
        time.sleep(0.5)
        audit("auth.password.change", False, {"reason": "current_password"})
        return jsonify(error="当前密码不正确"), 403
    if new_password != confirmation:
        return jsonify(error="两次输入的新密码不一致"), 400
    if new_password == current:
        return jsonify(error="新密码不能与当前密码相同"), 400
    error = password_policy(new_password)
    if error:
        return jsonify(error=error), 400
    write_password_hash(new_password)
    audit("auth.password.change", True, {})
    session.clear()
    return jsonify(ok=True, relogin=True)


@app.get("/api/status")
@require_auth
def status():
    g_ok, g_code = google_ok()
    p_ok, p_details = privacy_config()
    data = {
        "timestamp": datetime.now().astimezone().isoformat(timespec="seconds"),
        "services": {name: service_state(name) for name in SERVICES},
        "dns": {
            "privacy_healthy": p_ok,
            "privacy": p_details,
            "baidu_a": dig("baidu.com", "A")[:4],
            "domestic_aaaa": dig("www.gov.cn", "AAAA")[-4:],
            "google_a": dig("google.com", "A")[:6],
            "google_aaaa_empty": len(dig("google.com", "AAAA")) == 0,
            "path": "AdGuard → MosDNS → 国内域名：AliDNS/DNSPod DoH；全球域名：Mihomo 代理 → Cloudflare/Google DoH",
        },
        "google": {"healthy": g_ok, "http_code": g_code},
        "tproxy": tproxy_state(),
        "system": system_metrics(),
        "watchdog": load_watchdog(),
        "adguard": adguard_summary(),
        "provider": provider_status(),
        "connections": connections_summary(),
    }
    return jsonify(data)


@app.get("/api/mihomo/groups")
@require_auth
def proxy_groups(): return jsonify(mihomo_groups())

@app.get("/api/mihomo/preferred")
@require_auth
def preferred_status():
    try:data=json.loads(Path("/etc/bypass-router/mihomo/preferred-node.json").read_text())
    except Exception:data={"preferred":None}
    return jsonify(data)

@app.post("/api/mihomo/preferred")
@require_auth
def preferred_set():
    if not require_csrf():return jsonify(error="invalid csrf token"),403
    node=str((request.get_json(silent=True) or {}).get("node","")).strip()
    if not node:return jsonify(error="节点不能为空"),400
    rc,out=run(["/usr/local/sbin/mihomo-set-preferred",node],120)
    try:data=json.loads(out)
    except Exception:data={"ok":False,"error":"设置常用节点失败"}
    audit("proxy.preferred.set",rc==0,{"node":node})
    return jsonify(data),(200 if rc==0 else 400)

@app.post("/api/mihomo/select")
@require_auth
def proxy_select():
    if not require_csrf(): return jsonify(error="invalid csrf token"),403
    body=request.get_json(silent=True) or {}; group=str(body.get("group","")); node=str(body.get("node","")); groups={g["name"]:g for g in mihomo_groups().get("groups",[])}
    if group not in groups or not groups[group]["selectable"]: return jsonify(error="该策略组不可手动选择"),400
    if node not in {n["name"] for n in groups[group]["nodes"]}: return jsonify(error="节点不在策略组中"),400
    old_node=groups[group].get("now",""); path="/proxies/"+urllib.parse.quote(group,safe="")
    code,result=json_http(MIHOMO_API+path,"PUT",{"name":node},10)
    if code not in (200,204):
        audit("mihomo.select",False,{"group":group,"node":node}); return jsonify(error="节点切换失败"),502
    time.sleep(1); good,http_code=google_ok(); rolled_back=False
    if not good and old_node and old_node!=node:
        json_http(MIHOMO_API+path,"PUT",{"name":old_node},10); rolled_back=True
    audit("mihomo.select",good,{"group":group,"old":old_node,"new":node,"google_http":http_code,"rolled_back":rolled_back})
    if not good: return jsonify(error="新节点验证失败，已自动恢复旧节点",rolled_back=rolled_back),502
    return jsonify(ok=True,old=old_node,current=node,google_http=http_code)

@app.post("/api/mihomo/delay")
@require_auth
def proxy_delay():
    if not require_csrf(): return jsonify(error="invalid csrf token"),403
    node=str((request.get_json(silent=True) or {}).get("node","")); allowed={n["name"] for g in mihomo_groups().get("groups",[]) for n in g["nodes"]}
    if node not in allowed: return jsonify(error="未知节点"),400
    path="/proxies/%s/delay?timeout=5000&url=%s"%(urllib.parse.quote(node,safe=""),urllib.parse.quote("https://cp.cloudflare.com/generate_204",safe=""))
    code,result=json_http(MIHOMO_API+path,timeout=8); return jsonify(ok=code==200,**result),(200 if code==200 else 502)

@app.post("/api/mihomo/refresh")
@require_auth
def proxy_refresh():
    if not require_csrf():
        return jsonify(error="invalid csrf token"), 403
    rc, out = run(["systemctl", "start", "mihomo-provider-update.service"], 60)
    if rc != 0:
        return jsonify(error="订阅更新失败", output=out[-1500:]), 502
    code, data = json_http(MIHOMO_API + "/providers/proxies", timeout=8)
    if code != 200 or "main" not in data.get("providers", {}):
        return jsonify(error="订阅已下载，但 Mihomo 未加载 provider"), 502
    provider = data["providers"]["main"]
    result={"ok":True,"provider":"main","proxy_count":len(provider.get("proxies",[])),"updated_at":provider.get("updatedAt")}
    audit("mihomo.provider.refresh",True,{"proxy_count":result["proxy_count"]}); return jsonify(result)

@app.post("/api/service/<name>/<verb>")
@require_auth
def service_action(name,verb):
    if not require_csrf(): return jsonify(error="invalid csrf token"),403
    if verb not in SAFE_SERVICE_VERBS.get(name,set()): return jsonify(error="该操作未开放；管理链路和防火墙不可从网页停用"),403
    rc,out=run(["systemctl",verb,name],50); state=service_state(name); audit("service."+verb,rc==0,{"service":name,"state":state})
    return jsonify(ok=rc==0,state=state,output=out[-1500:]),(200 if rc==0 else 500)

@app.post("/api/adguard/protection")
@require_auth
def adguard_protection():
    if not require_csrf(): return jsonify(error="invalid csrf token"),403
    enabled=bool((request.get_json(silent=True) or {}).get("enabled")); code,result=json_http(ADGUARD_API+"/control/protection","POST",{"protection_enabled":enabled},10)
    return jsonify(ok=code==200,result=result),(200 if code==200 else 502)

@app.post("/api/adguard/filters/refresh")
@require_auth
def adguard_filter_refresh():
    if not require_csrf(): return jsonify(error="invalid csrf token"),403
    code,result=json_http(ADGUARD_API+"/control/filtering/refresh","POST",{"whitelist":True},45); return jsonify(ok=code==200,result=result),(200 if code==200 else 502)

@app.route("/adguard/", defaults={"subpath": ""}, methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
@app.route("/adguard/<path:subpath>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
@app.route("/control/<path:subpath>", methods=["GET", "POST", "PUT", "DELETE", "PATCH"])
@require_auth
def adguard_proxy(subpath):
    prefix = "/control/" if request.path.startswith("/control/") else "/"
    target = ADGUARD_API + prefix + subpath
    if request.query_string:
        target += "?" + request.query_string.decode()
    data=request.get_data() if request.method in {"POST","PUT","PATCH"} else None; req=urllib.request.Request(target,data=data,method=request.method)
    for h in ("Content-Type","Accept"):
        if request.headers.get(h): req.add_header(h,request.headers[h])
    try:
        with urllib.request.urlopen(req,timeout=30) as resp:
            body=resp.read(); ct=resp.headers.get("Content-Type","application/octet-stream")
            if not subpath and "text/html" in ct:
                text=body.decode(errors="replace"); text=re.sub(r'(?P<a>(?:src|href)=")(?!(?:https?:|/|#))',r'\g<a>/adguard/',text); text=text.replace('<head>','<head><base href="/adguard/">',1); body=text.encode()
            return Response(body,status=resp.status,content_type=ct)
    except urllib.error.HTTPError as exc: return Response(exc.read(),status=exc.code,content_type=exc.headers.get("Content-Type","text/plain"))

@app.post("/api/action/<action>")
@require_auth
def action(action: str):
    if not require_csrf():
        return jsonify(error="invalid csrf token"), 403
    cmd = ALLOWED_ACTIONS.get(action)
    if not cmd:
        return jsonify(error="unsupported action"), 404
    rc, out = run(cmd, 90)
    return jsonify(ok=rc == 0, action=action, output=out[-3000:], rc=rc), (200 if rc == 0 else 500)


@app.post("/api/mihomo/delay-all")
@require_auth
def proxy_delay_all():
    if not require_csrf():
        return jsonify(error="invalid csrf token"), 403
    code, _ = json_http(MIHOMO_API + "/providers/proxies/main/healthcheck", timeout=35)
    if code not in (200, 204):
        audit("mihomo.delay_all", False, {"provider": "main"})
        return jsonify(error="Provider 批量健康检查失败"), 502
    code, provider = json_http(MIHOMO_API + "/providers/proxies/main", timeout=8)
    results = []
    if code == 200:
        for node in provider.get("proxies", []):
            history = node.get("history") or []
            delay = history[-1].get("delay") if history else None
            results.append({"name": node.get("name"), "ok": bool(delay), "delay": delay})
    success = sum(1 for x in results if x["ok"])
    audit("mihomo.delay_all", success > 0, {"nodes": len(results), "success": success})
    return jsonify(ok=success > 0, results=results)

def registry_call(args,timeout=75):
    rc,out=run(["/usr/local/sbin/mihomo-subscription-registry"]+args,timeout)
    try:data=json.loads(out)
    except Exception:data={"ok":False,"error":"订阅管理操作失败"}
    return rc,data

@app.get("/api/mihomo/subscriptions")
@require_auth
def subscriptions_list():
    rc,data=registry_call(["list"],15);return jsonify(data),(200 if rc==0 else 500)

@app.post("/api/mihomo/subscriptions")
@require_auth
def subscriptions_add():
    if not require_csrf():return jsonify(error="invalid csrf token"),403
    b=request.get_json(silent=True) or {};rc,data=registry_call(["add","--name",str(b.get("name","")),"--url",str(b.get("url",""))])
    audit("subscription.add",rc==0,{"id":data.get("id"),"host":data.get("host"),"proxy_count":data.get("proxy_count")});return jsonify(data),(200 if rc==0 else 400)

@app.patch("/api/mihomo/subscriptions/<sid>")
@require_auth
def subscriptions_edit(sid):
    if not require_csrf():return jsonify(error="invalid csrf token"),403
    b=request.get_json(silent=True) or {};args=["edit","--id",sid]
    if "name" in b:args += ["--name",str(b["name"])]
    if b.get("url"):args += ["--url",str(b["url"])]
    if "enabled" in b:args += ["--enabled","true" if b["enabled"] else "false"]
    rc,data=registry_call(args);audit("subscription.edit",rc==0,{"id":sid,"host":data.get("host")});return jsonify(data),(200 if rc==0 else 400)

@app.delete("/api/mihomo/subscriptions/<sid>")
@require_auth
def subscriptions_delete(sid):
    if not require_csrf():return jsonify(error="invalid csrf token"),403
    rc,data=registry_call(["delete","--id",sid],20);audit("subscription.delete",rc==0,{"id":sid});return jsonify(data),(200 if rc==0 else 400)

@app.post("/api/mihomo/subscriptions/<sid>/update")
@require_auth
def subscriptions_update(sid):
    if not require_csrf():return jsonify(error="invalid csrf token"),403
    rc,data=registry_call(["update","--id",sid]);audit("subscription.update",rc==0,{"id":sid,"proxy_count":data.get("proxy_count")});return jsonify(data),(200 if rc==0 else 502)

@app.post("/api/mihomo/subscriptions/<sid>/activate")
@require_auth
def subscriptions_activate(sid):
    if not require_csrf():return jsonify(error="invalid csrf token"),403
    rc,data=registry_call(["activate","--id",sid]);audit("subscription.activate",rc==0,{"id":sid,"host":data.get("host"),"proxy_count":data.get("proxy_count")});return jsonify(data),(200 if rc==0 else 502)

@app.post("/api/mihomo/subscriptions/<sid>/move")
@require_auth
def subscriptions_move(sid):
    if not require_csrf():return jsonify(error="invalid csrf token"),403
    delta=int((request.get_json(silent=True) or {}).get("delta",0));
    if delta not in (-1,1):return jsonify(error="invalid delta"),400
    rc,data=registry_call(["move","--id",sid,"--delta",str(delta)],20);return jsonify(data),(200 if rc==0 else 400)

@app.get("/api/mihomo/subscription")
@require_auth
def subscription_status():
    rc,out=run(["/usr/local/sbin/mihomo-subscription-manage","status"],15)
    try:data=json.loads(out)
    except Exception:data={"configured":False,"error":"无法读取订阅状态"}
    return jsonify(data),(200 if rc==0 else 500)

@app.post("/api/mihomo/subscription/preview")
@require_auth
def subscription_preview():
    if not require_csrf(): return jsonify(error="invalid csrf token"),403
    url=str((request.get_json(silent=True) or {}).get("url","")).strip()
    if len(url)>2048: return jsonify(error="订阅URL过长"),400
    rc,out=run(["/usr/local/sbin/mihomo-subscription-manage","preview","--url",url],60)
    try:data=json.loads(out)
    except Exception:data={"ok":False,"error":"订阅预检失败"}
    audit("mihomo.subscription.preview",rc==0,{"host":data.get("host"),"new_count":data.get("new_count")})
    return jsonify(data),(200 if rc==0 else 400)

@app.post("/api/mihomo/subscription/apply")
@require_auth
def subscription_apply():
    if not require_csrf(): return jsonify(error="invalid csrf token"),403
    token=str((request.get_json(silent=True) or {}).get("token","")).strip()
    rc,out=run(["/usr/local/sbin/mihomo-subscription-manage","apply","--token",token],75)
    try:data=json.loads(out)
    except Exception:data={"ok":False,"error":"订阅切换失败"}
    audit("mihomo.subscription.apply",rc==0,{"host":data.get("host"),"proxy_count":data.get("proxy_count"),"backup":data.get("backup")})
    return jsonify(data),(200 if rc==0 else 502)

def rule_call(args,timeout=75):
    rc,out=run(["/usr/local/sbin/mihomo-rule-manage"]+args,timeout)
    try:data=json.loads(out)
    except Exception:data={"ok":False,"error":"分流规则操作失败"}
    return rc,data

@app.get("/api/mihomo/rules")
@require_auth
def rules_list():
    rc,data=rule_call(["list"],15)
    # Include live rule hit counters without exposing configuration secrets.
    code,live=json_http(MIHOMO_API+"/rules",timeout=10)
    data["live_rules"]=(live.get("rules",[]) if code==200 else [])[:1000]
    return jsonify(data),(200 if rc==0 else 500)

@app.post("/api/mihomo/rules")
@require_auth
def rules_add():
    if not require_csrf():return jsonify(error="invalid csrf token"),403
    b=request.get_json(silent=True) or {}
    args=["add","--type",str(b.get("type","")),"--payload",str(b.get("payload","")),"--target",str(b.get("target",""))]
    if b.get("note"):args += ["--note",str(b["note"])]
    rc,data=rule_call(args);audit("rule.add",rc==0,{"type":b.get("type"),"target":b.get("target")});return jsonify(data),(200 if rc==0 else 400)

@app.patch("/api/mihomo/rules/<rid>")
@require_auth
def rules_edit(rid):
    if not require_csrf():return jsonify(error="invalid csrf token"),403
    b=request.get_json(silent=True) or {};args=["edit","--id",rid]
    for key in ("type","payload","target","note"):
        if key in b:args += ["--"+key,str(b[key])]
    if "enabled" in b:args += ["--enabled","true" if b["enabled"] else "false"]
    rc,data=rule_call(args);audit("rule.edit",rc==0,{"id":rid,"target":b.get("target"),"enabled":b.get("enabled")});return jsonify(data),(200 if rc==0 else 400)

@app.delete("/api/mihomo/rules/<rid>")
@require_auth
def rules_delete(rid):
    if not require_csrf():return jsonify(error="invalid csrf token"),403
    rc,data=rule_call(["delete","--id",rid]);audit("rule.delete",rc==0,{"id":rid});return jsonify(data),(200 if rc==0 else 400)

@app.post("/api/mihomo/rules/<rid>/move")
@require_auth
def rules_move(rid):
    if not require_csrf():return jsonify(error="invalid csrf token"),403
    delta=int((request.get_json(silent=True) or {}).get("delta",0))
    if delta not in (-1,1):return jsonify(error="invalid delta"),400
    rc,data=rule_call(["move","--id",rid,"--delta",str(delta)]);return jsonify(data),(200 if rc==0 else 400)

@app.get("/api/mihomo/rule-analysis")
@require_auth
def rule_analysis():
    code,rules_data=json_http(MIHOMO_API+"/rules",timeout=12)
    code2,conn_data=json_http(MIHOMO_API+"/connections",timeout=10)
    rules=rules_data.get("rules",[]) if code==200 else []
    conns=conn_data.get("connections",[]) if code2==200 else []
    service_names={"Netflix","国外媒体","国内媒体","微软服务","Telegram","Apple 服务","代理节点","自动选择","故障转移","DIRECT","REJECT"}
    by_key={}; exact_conflicts=[]; suffix_rules=[]
    for r in rules:
        kind=str(r.get("type",""));payload=str(r.get("payload","")).lower();target=str(r.get("proxy",""));index=int(r.get("index",0));hits=int((r.get("extra") or {}).get("hitCount",0) or 0)
        key=(kind,payload)
        if key in by_key and by_key[key]["target"]!=target:
            exact_conflicts.append({"type":kind,"payload":payload,"first_target":by_key[key]["target"],"first_index":by_key[key]["index"],"later_target":target,"later_index":index})
        else: by_key[key]={"target":target,"index":index}
        if kind=="DomainSuffix" and payload:suffix_rules.append((payload,target,index))
    # Detect broader suffix rules that shadow a later, more specific suffix with another target.
    suffix_conflicts=[]
    for payload,target,index in suffix_rules:
        for broad,btarget,bindex in suffix_rules:
            if bindex>=index or target==btarget or payload==broad:continue
            if payload.endswith("."+broad):
                suffix_conflicts.append({"specific":payload,"specific_target":target,"specific_index":index,"earlier_suffix":broad,"earlier_target":btarget,"earlier_index":bindex});break
    stats={name:{"connections":0,"download":0,"upload":0,"rule_hits":0,"last_hit":None} for name in service_names}
    for r in rules:
        target=str(r.get("proxy",""));extra=r.get("extra") or {}
        if target in stats:
            stats[target]["rule_hits"]+=int(extra.get("hitCount",0) or 0)
            hit=extra.get("hitAt")
            if hit and hit!="1970-01-01T08:00:00+08:00" and (not stats[target]["last_hit"] or hit>stats[target]["last_hit"]):stats[target]["last_hit"]=hit
    for c in conns:
        chains=c.get("chains") or []
        target=next((x for x in reversed(chains) if x in stats),None)
        if not target:
            rule=str(c.get("rulePayload") or c.get("rule_payload") or "")
            target=rule if rule in stats else None
        if target:
            stats[target]["connections"]+=1;stats[target]["download"]+=int(c.get("download",0) or 0);stats[target]["upload"]+=int(c.get("upload",0) or 0)
    return jsonify(rule_count=len(rules),exact_conflicts=exact_conflicts[:100],suffix_conflicts=suffix_conflicts[:100],conflict_count=len(exact_conflicts)+len(suffix_conflicts),stats=stats)

@app.get("/api/mihomo/connections")
@require_auth
def proxy_connections():
    code,data=json_http(MIHOMO_API+"/connections",timeout=8)
    if code!=200: return jsonify(error="无法读取连接"),502
    items=[]
    for c in data.get("connections",[]):
        m=c.get("metadata") or {}; host=m.get("host") or m.get("destinationIP") or m.get("remoteDestination") or "—"
        items.append({"id":c.get("id"),"host":host,"network":m.get("network"),"type":m.get("type"),"source":m.get("sourceIP"),"source_port":m.get("sourcePort"),"destination_port":m.get("destinationPort"),"inbound":m.get("inboundName"),"upload":c.get("upload",0),"download":c.get("download",0),"start":c.get("start"),"chains":c.get("chains",[]),"rule":c.get("rule"),"rule_payload":c.get("rulePayload")})
    return jsonify(upload_total=data.get("uploadTotal",0),download_total=data.get("downloadTotal",0),memory=data.get("memory",0),connections=items)

@app.delete("/api/mihomo/connections/<connection_id>")
@require_auth
def proxy_connection_close(connection_id):
    if not require_csrf(): return jsonify(error="invalid csrf token"),403
    if not re.fullmatch(r"[0-9a-fA-F-]{36}",connection_id): return jsonify(error="invalid connection id"),400
    code,data=json_http(MIHOMO_API+"/connections",timeout=8); allowed={c.get("id") for c in data.get("connections",[])} if code==200 else set()
    if connection_id not in allowed: return jsonify(error="连接不存在"),404
    code,result=json_http(MIHOMO_API+"/connections/"+connection_id,"DELETE",timeout=8); ok=code in (200,204)
    audit("mihomo.connection.close",ok,{"id":connection_id}); return jsonify(ok=ok),(200 if ok else 502)

@app.delete("/api/mihomo/connections")
@require_auth
def proxy_connections_close_all():
    if not require_csrf(): return jsonify(error="invalid csrf token"),403
    code,result=json_http(MIHOMO_API+"/connections","DELETE",timeout=10); ok=code in (200,204)
    audit("mihomo.connections.close_all",ok,{}); return jsonify(ok=ok),(200 if ok else 502)

@app.post("/api/mihomo/best")
@require_auth
def proxy_best():
    if not require_csrf(): return jsonify(error="invalid csrf token"),403
    body=request.get_json(silent=True) or {}; group=str(body.get("group","代理节点")); groups={g["name"]:g for g in mihomo_groups().get("groups",[])}
    if group not in groups or not groups[group]["selectable"]: return jsonify(error="策略组不可手动选择"),400
    code,_=json_http(MIHOMO_API+"/providers/proxies/main/healthcheck",timeout=35)
    if code not in (200,204): return jsonify(error="批量测速失败"),502
    code,provider=json_http(MIHOMO_API+"/providers/proxies/main",timeout=8); candidates=[]
    allowed={n["name"] for n in groups[group]["nodes"]}
    for node in provider.get("proxies",[]) if code==200 else []:
        history=node.get("history") or []; delay=history[-1].get("delay") if history else 0
        if node.get("name") in allowed and node.get("alive",True) and delay: candidates.append((delay,node.get("name")))
    if not candidates: return jsonify(error="没有可用节点"),502
    delay,node=min(candidates); old=groups[group].get("now",""); path="/proxies/"+urllib.parse.quote(group,safe="")
    code,_=json_http(MIHOMO_API+path,"PUT",{"name":node},10)
    if code not in (200,204): return jsonify(error="最佳节点切换失败"),502
    time.sleep(1); good,http_code=google_ok(); rolled=False
    if not good and old and old!=node: json_http(MIHOMO_API+path,"PUT",{"name":old},10); rolled=True
    audit("mihomo.select_best",good,{"group":group,"old":old,"new":node,"delay":delay,"google_http":http_code,"rolled_back":rolled})
    if not good: return jsonify(error="最佳节点无法访问Google，已回滚",rolled_back=rolled),502
    return jsonify(ok=True,node=node,delay=delay,google_http=http_code,old=old)

@app.get("/api/mihomo/provider-nodes")
@require_auth
def provider_nodes():
    code,p=json_http(MIHOMO_API+"/providers/proxies/main",timeout=8)
    if code!=200: return jsonify(error="Provider不可用"),502
    nodes=[]
    for n in p.get("proxies",[]):
        hist=n.get("history") or []; nodes.append({"name":n.get("name"),"alive":n.get("alive"),"delay":hist[-1].get("delay") if hist else None,"history":hist[-8:]})
    return jsonify(name=p.get("name"),type=p.get("vehicleType"),updated_at=p.get("updatedAt"),test_url=p.get("testUrl"),nodes=nodes)

@app.get("/api/provider/status")
@require_auth
def provider_status_api(): return jsonify(provider_status())

@app.post("/api/diagnostics")
@require_auth
def diagnostics_api():
    if not require_csrf(): return jsonify(error="invalid csrf token"),403
    checks=diagnostics(); ok=all(x["ok"] for x in checks); audit("diagnostics.run",ok,{"passed":sum(1 for x in checks if x["ok"]),"total":len(checks)})
    return jsonify(ok=ok,checks=checks,timestamp=datetime.now().astimezone().isoformat(timespec="seconds"))

@app.get("/api/audit")
@require_auth
def audit_api():
    try: data=[json.loads(x) for x in reversed(AUDIT_LOG.read_text().splitlines()[-150:]) if x.strip()]
    except Exception: data=[]
    return jsonify(events=data)


@app.get("/api/logs")
@require_auth
def logs():
    rc, out = run(["journalctl", "-u", "mihomo", "-u", "mosdns", "-u", "adguardhome",
                   "-u", "bypass-router-tproxy", "--since", "-30 min", "--no-pager",
                   "-n", "120", "-o", "short-iso"], 12)
    # Redact common token/credential patterns before returning.
    out = re.sub(r"(?i)(token|password|passwd|secret|uuid|authorization)[=: ]+[^\s,]+", r"\1=[REDACTED]", out)
    out = re.sub(r"https?://[^\s]+(?:subscribe|subscription)[^\s]*", "[REDACTED_URL]", out)
    return Response(out if rc == 0 else "无法读取日志", mimetype="text/plain")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8443)
