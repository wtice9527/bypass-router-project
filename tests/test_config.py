import json
from pathlib import Path

import pytest
import yaml

from routerctl.config import load, load_secrets, render_tree

ROOT = Path(__file__).parents[1]


def write(tmp_path, data):
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data))
    return path


def test_example_valid():
    config = load(ROOT / "config.example.json")
    assert config["router_ipv4"] == "192.168.50.2"
    assert config["strict_dns"] is True


def test_router_must_be_in_lan(tmp_path):
    path = write(tmp_path, {"router_ipv4": "10.0.0.2"})
    with pytest.raises(ValueError):
        load(path)


def test_plain_public_dns_is_rejected(tmp_path):
    path = write(tmp_path, {"global_doh": ["8.8.8.8"]})
    with pytest.raises(ValueError, match="DoH/DoT"):
        load(path)


def test_strict_dns_cannot_be_disabled(tmp_path):
    path = write(tmp_path, {"strict_dns": False})
    with pytest.raises(ValueError, match="strict_dns"):
        load(path)


def test_render_has_no_placeholders(tmp_path):
    config = load(ROOT / "config.example.json")
    out = tmp_path / "out"
    render_tree(ROOT / "templates", out, config)
    for path in out.rglob("*"):
        if path.is_file():
            assert "{{" not in path.read_text()


def test_rendered_dns_is_encrypted_only(tmp_path):
    config = load(ROOT / "config.example.json")
    out = tmp_path / "out"
    render_tree(ROOT / "templates", out, config)
    mosdns = yaml.safe_load((out / "mosdns/config.yaml").read_text())
    forwards = [x for x in mosdns["plugins"] if x.get("type") == "forward"]
    addresses = [u["addr"] for f in forwards for u in f["args"]["upstreams"]]
    assert addresses
    assert all(x.startswith(("https://", "tls://")) for x in addresses)
    adguard = yaml.safe_load((out / "adguardhome/AdGuardHome.yaml").read_text())
    assert adguard["dns"]["upstream_dns"] == ["127.0.0.1:5335"]
    assert adguard["dns"]["fallback_dns"] == []


def test_secrets_required(tmp_path):
    path = tmp_path / "secrets.json"
    path.write_text(json.dumps({"subscription_url": "CHANGE_ME", "web_admin_password": "CHANGE_ME"}))
    with pytest.raises(ValueError):
        load_secrets(path, required=True)


def test_no_production_identity_in_project():
    forbidden = ["192.168.10.112", "100.97.58.127", "acck-jp-", "entry-usa-"]
    for path in ROOT.rglob("*"):
        if not path.is_file() or any(x in path.parts for x in {".git", ".venv", "build", "release"}):
            continue
        try:
            text = path.read_text()
        except UnicodeDecodeError:
            continue
        if path.name in {"scan-secrets.py", "test_config.py", "check-secrets.py"}:
            continue
        for value in forbidden:
            assert value not in text, f"{value} leaked in {path}"


def test_web_access_scope_is_parameterized():
    app = (ROOT / "assets/web/app.py").read_text()
    html = (ROOT / "assets/web/static/index.html").read_text()
    assert 'BYPASS_ROUTER_LAN_CIDR' in app
    assert '192.168.10.0/24' not in app
    assert '192.168.10.105' not in html
