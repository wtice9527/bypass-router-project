import json
from pathlib import Path

from routerctl.cli import apply, rollback, status, uninstall

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
