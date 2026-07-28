import json
from pathlib import Path

from routerctl.cli import apply, rollback, status, uninstall, stop_managed_services

ROOT = Path(__file__).parents[1]


def make_secrets(tmp_path):
    path = tmp_path / "secrets.json"
    path.write_text(json.dumps({
        "subscription_url": "https://example.com/subscription",
        "web_admin_password": "Example-Only-Password-2026!",
    }))
    return path


def test_isolated_install_upgrade_rollback_uninstall(tmp_path, capsys):
    prefix = tmp_path / "rootfs"
    secrets = make_secrets(tmp_path)
    config = str(ROOT / "config.example.json")

    apply(config, str(secrets), str(prefix), True, "install")
    manifest = prefix / "var/lib/bypass-router-project/manifest.json"
    assert manifest.exists()
    data = json.loads(manifest.read_text())
    assert data["version"] == (ROOT / "VERSION").read_text().strip()
    assert (prefix / "etc/bypass-router/mihomo/config.yaml").exists()
    assert (prefix / "var/lib/mihomo/providers/main.yaml").read_text() == "proxies: []\n"
    assert (prefix / "var/lib/adguardhome").is_dir()
    assert (prefix / "var/log/bypass-router").is_dir()
    assert not (prefix / "etc/bypass-router/mihomo/providers/main.yaml").exists()
    assert (prefix / "opt/bypass-router-web/app.py").exists()
    assert (prefix / "etc/bypass-router/mihomo/secrets/provider-url").stat().st_mode & 0o777 == 0o600

    apply(config, str(secrets), str(prefix), True, "upgrade")
    status(str(prefix))
    assert '"drift": []' in capsys.readouterr().out

    web = prefix / "opt/bypass-router-web/app.py"
    web.write_text("broken")
    status(str(prefix))
    assert "opt/bypass-router-web/app.py" in capsys.readouterr().out

    rollback(str(prefix), None, True)
    assert web.read_text() != "broken"

    uninstall(str(prefix), True)
    assert not manifest.exists()
    assert not (prefix / "etc/bypass-router/mihomo/config.yaml").exists()


def test_generated_or_installed_files_do_not_contain_plain_password(tmp_path):
    prefix = tmp_path / "rootfs"
    secrets = make_secrets(tmp_path)
    cleartext = "Example-Only-" + "Password-2026!"
    apply(str(ROOT / "config.example.json"), str(secrets), str(prefix), True, "install")
    for path in prefix.rglob("*"):
        if path.is_file():
            try:
                assert cleartext not in path.read_text()
            except UnicodeDecodeError:
                pass


def test_release_makefile_excludes_local_secret_files():
    makefile = (ROOT / "Makefile").read_text()
    for value in ("./config.json", "./secrets.json", "./.env", "./.env.*"):
        assert value in makefile


def test_installed_web_unit_loads_rendered_lan_access_scope(tmp_path):
    prefix = tmp_path / "rootfs"
    secrets = make_secrets(tmp_path)
    config_path = tmp_path / "config.json"
    config_path.write_text(json.dumps({
        "router_ipv4": "192.168.88.2",
        "lan_cidr": "192.168.88.0/24",
        "upstream_gateway": "192.168.88.1",
        "enable_tailscale_access": False,
    }))
    apply(str(config_path), str(secrets), str(prefix), True, "install")
    web_env = (prefix / "etc/bypass-router-web/web.env").read_text()
    unit = (prefix / "etc/systemd/system/bypass-router-web.service").read_text()
    assert "BYPASS_ROUTER_LAN_CIDR=192.168.88.0/24" in web_env
    assert "BYPASS_ROUTER_ALLOW_TAILSCALE=false" in web_env
    assert "EnvironmentFile=-/etc/bypass-router-web/web.env" in unit


def test_failure_cleanup_stops_units_before_file_restore(monkeypatch):
    calls = []
    monkeypatch.setattr("routerctl.cli.run", lambda cmd, check=True, timeout=120: calls.append(cmd))
    stop_managed_services(Path("/"))
    assert ["systemctl", "stop", "bypass-router-tproxy.service"] in calls
    assert ["systemctl", "stop", "bypass-router-input-guard.service"] in calls
    assert ["systemctl", "stop", "bypass-router-watchdog.timer"] in calls
