import json
from pathlib import Path

import pytest

from routerctl import wizard


def test_detect_defaults_parses_default_route_and_interface(monkeypatch):
    outputs = {
        ("ip", "-j", "route", "show", "default"): '[{"dst":"default","gateway":"192.168.88.1","dev":"enp1s0"}]',
        ("ip", "-j", "addr", "show", "dev", "enp1s0"): '[{"addr_info":[{"family":"inet","local":"192.168.88.20","prefixlen":24,"scope":"global"}]}]',
    }
    monkeypatch.setattr(wizard, "command_output", lambda cmd: outputs.get(tuple(cmd), ""))
    detected = wizard.detect_network_defaults()
    assert detected["interface"] == "enp1s0"
    assert detected["upstream_gateway"] == "192.168.88.1"
    assert detected["router_ipv4"] == "192.168.88.20"
    assert detected["lan_cidr"] == "192.168.88.0/24"


def test_detect_defaults_handles_missing_route(monkeypatch):
    monkeypatch.setattr(wizard, "command_output", lambda cmd: "")
    assert wizard.detect_network_defaults() == {}


def test_detect_ssh_port_reads_active_sshd_listener(monkeypatch):
    monkeypatch.setattr(wizard, "command_output", lambda cmd: "LISTEN 0 128 0.0.0.0:2222 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\n")
    assert wizard.detect_ssh_port() == 2222


def test_collect_answers_reprompts_after_invalid_lan_cidr(monkeypatch):
    answers = iter([
        "eth0", "not-a-cidr", "192.168.50.0/24", "192.168.50.2", "192.168.50.1",
        "n", "0.0.0.0", "8443", "22", "y", "", "", "", "", "",
        "https://example.com/sub", "Strong-Example-Password-2026!", "Strong-Example-Password-2026!",
    ])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    monkeypatch.setattr(wizard.getpass, "getpass", lambda prompt="": next(answers))
    config, _ = wizard.collect_answers({})
    assert config["lan_cidr"] == "192.168.50.0/24"


def test_collect_answers_reprompts_after_invalid_boolean(monkeypatch):
    answers = iter([
        "eth0", "192.168.50.0/24", "192.168.50.2", "192.168.50.1",
        "maybe", "n", "0.0.0.0", "8443", "22", "y", "", "", "", "", "",
        "https://example.com/sub", "Strong-Example-Password-2026!", "Strong-Example-Password-2026!",
    ])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    monkeypatch.setattr(wizard.getpass, "getpass", lambda prompt="": next(answers))
    config, _ = wizard.collect_answers({})
    assert config["manage_network"] is False


def test_build_answers_produces_valid_config_and_secrets(monkeypatch):
    answers = iter([
        "enp1s0", "192.168.88.0/24", "192.168.88.2", "192.168.88.1",
        "n", "0.0.0.0", "8443", "22", "y", "", "", "", "", "",
        "https://example.com/sub", "Strong-Example-Password-2026!", "Strong-Example-Password-2026!",
    ])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    monkeypatch.setattr(wizard.getpass, "getpass", lambda prompt="": next(answers))
    config, secrets = wizard.collect_answers({})
    assert config["interface"] == "enp1s0"
    assert config["router_ipv4"] == "192.168.88.2"
    assert config["upstream_gateway"] == "192.168.88.1"
    assert config["manage_network"] is False
    assert secrets["subscription_url"] == "https://example.com/sub"
    assert secrets["web_admin_password"] == "Strong-Example-Password-2026!"


def test_collect_answers_rejects_mismatched_password(monkeypatch):
    answers = iter([
        "eth0", "192.168.50.0/24", "192.168.50.2", "192.168.50.1",
        "n", "0.0.0.0", "8443", "22", "y", "", "", "", "", "",
        "https://example.com/sub", "Strong-Example-Password-2026!", "different-password",
    ])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    monkeypatch.setattr(wizard.getpass, "getpass", lambda prompt="": next(answers))
    with pytest.raises(ValueError, match="两次输入的密码不一致"):
        wizard.collect_answers({})


def test_write_answers_uses_private_secret_permissions(tmp_path):
    config = {"interface": "eth0"}
    secrets = {"subscription_url": "https://example.com/sub", "web_admin_password": "Strong-Example-Password-2026!"}
    config_path = tmp_path / "config.json"
    secrets_path = tmp_path / "secrets.json"
    wizard.write_answers(config, secrets, config_path, secrets_path)
    assert json.loads(config_path.read_text()) == config
    assert json.loads(secrets_path.read_text()) == secrets
    assert secrets_path.stat().st_mode & 0o777 == 0o600


def test_config_supports_optional_network_management(tmp_path):
    from routerctl.config import load

    path = tmp_path / "config.json"
    path.write_text(json.dumps({
        "manage_network": True,
        "network_connection": "Wired connection 1",
        "interface": "enp1s0",
    }))
    config = load(path)
    assert config["manage_network"] is True
    assert config["network_connection"] == "Wired connection 1"


def test_collect_answers_requires_detected_networkmanager_connection(monkeypatch):
    answers = iter([
        "enp1s0", "192.168.88.0/24", "192.168.88.2", "192.168.88.1",
        "y", "0.0.0.0", "8443", "22", "y", "", "", "", "", "",
        "https://example.com/sub", "Strong-Example-Password-2026!", "Strong-Example-Password-2026!",
    ])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    monkeypatch.setattr(wizard.getpass, "getpass", lambda prompt="": next(answers))
    monkeypatch.setattr(wizard, "detect_networkmanager_connection", lambda interface: "")
    with pytest.raises(ValueError, match="NetworkManager 连接"):
        wizard.collect_answers({})


def test_networkmanager_commands_use_router_address_gateway_and_local_dns():
    config = {
        "network_connection": "Wired connection 1",
        "router_ipv4": "192.168.88.2",
        "lan_cidr": "192.168.88.0/24",
        "upstream_gateway": "192.168.88.1",
    }
    commands = wizard.networkmanager_commands(config)
    assert commands[0] == [
        "nmcli", "connection", "modify", "Wired connection 1",
        "ipv4.method", "manual",
        "ipv4.addresses", "192.168.88.2/24",
        "ipv4.gateway", "192.168.88.1",
        "ipv4.dns", "192.168.88.2",
        "ipv4.ignore-auto-dns", "yes",
    ]
    assert commands[1] == ["nmcli", "connection", "up", "Wired connection 1"]


def test_networkmanager_commands_require_connection_name():
    with pytest.raises(ValueError, match="NetworkManager 连接名称"):
        wizard.networkmanager_commands({
            "network_connection": "",
            "router_ipv4": "192.168.88.2",
            "lan_cidr": "192.168.88.0/24",
            "upstream_gateway": "192.168.88.1",
        })


def test_rendered_project_enables_ipv4_forwarding_and_uses_configured_ssh_port(tmp_path):
    from routerctl.config import load, render_tree

    root = Path(__file__).parents[1]
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"ssh_port": 2222}))
    config = load(config_path)
    out = tmp_path / "out"
    render_tree(root / "templates", out, config)
    sysctl = (out / "sysctl/99-bypass-router.conf").read_text()
    guard = (out / "nftables/input-guard.nft").read_text()
    assert "net.ipv4.ip_forward = 1" in sysctl
    assert "tcp dport { 2222, 8443 } accept" in guard


def test_tailscale_rules_are_absent_when_disabled(tmp_path):
    from routerctl.config import load, render_tree

    root = Path(__file__).parents[1]
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({"enable_tailscale_access": False}))
    config = load(config_path)
    out = tmp_path / "out"
    render_tree(root / "templates", out, config)
    guard = (out / "nftables/input-guard.nft").read_text()
    assert "tailscale0" not in guard
    assert "41641" not in guard
