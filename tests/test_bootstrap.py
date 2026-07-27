import hashlib
import json

import pytest

from routerctl.bootstrap import (
    install_bootstrap_binaries, select_release_asset,
    should_proxy_subscription_fetch, verify_asset_digest,
)


def test_select_release_asset_prefers_exact_architecture_archive():
    assets = [
        {"name": "mihomo-linux-arm64-v1.2.3.gz", "browser_download_url": "arm"},
        {"name": "mihomo-linux-amd64-v1.2.3.gz", "browser_download_url": "amd"},
        {"name": "checksums.txt", "browser_download_url": "sum"},
    ]
    assert select_release_asset(assets, r"mihomo-linux-amd64-.*\.gz$") == "amd"


def test_select_release_asset_returns_none_when_missing():
    assert select_release_asset([], r"missing") is None


def test_install_bootstrap_binaries_skips_existing_commands(tmp_path, monkeypatch):
    config = {"install_dependencies": False, "install_mihomo": True, "install_mosdns": True, "install_adguardhome": True}
    monkeypatch.setattr("routerctl.bootstrap.shutil.which", lambda name: f"/usr/local/bin/{name}")
    called = []
    monkeypatch.setattr("routerctl.bootstrap.install_mihomo", lambda: called.append("mihomo"))
    monkeypatch.setattr("routerctl.bootstrap.install_mosdns", lambda: called.append("mosdns"))
    monkeypatch.setattr("routerctl.bootstrap.install_adguardhome", lambda: called.append("adguard"))
    install_bootstrap_binaries(config)
    assert called == []


def test_install_bootstrap_binaries_installs_missing_commands(monkeypatch):
    config = {"install_dependencies": False, "install_mihomo": True, "install_mosdns": True, "install_adguardhome": True}
    monkeypatch.setattr("routerctl.bootstrap.shutil.which", lambda name: None)
    called = []
    monkeypatch.setattr("routerctl.bootstrap.install_mihomo", lambda: called.append("mihomo"))
    monkeypatch.setattr("routerctl.bootstrap.install_mosdns", lambda: called.append("mosdns"))
    monkeypatch.setattr("routerctl.bootstrap.install_adguardhome", lambda: called.append("adguard"))
    install_bootstrap_binaries(config)
    assert called == ["mihomo", "mosdns", "adguard"]


def test_initial_subscription_fetch_is_direct_when_provider_is_empty(tmp_path):
    provider = tmp_path / "main.yaml"
    provider.write_text("proxies: []\n")
    assert should_proxy_subscription_fetch(provider) is False


def test_subscription_refresh_uses_proxy_after_nodes_exist(tmp_path):
    provider = tmp_path / "main.yaml"
    provider.write_text("proxies:\n  - {name: demo, type: ss}\n")
    assert should_proxy_subscription_fetch(provider) is True


def test_verify_asset_digest_accepts_matching_sha256(tmp_path):
    path = tmp_path / "asset"
    path.write_bytes(b"verified")
    digest = "sha256:" + hashlib.sha256(b"verified").hexdigest()
    verify_asset_digest(path, digest)


def test_verify_asset_digest_rejects_missing_or_wrong_digest(tmp_path):
    path = tmp_path / "asset"
    path.write_bytes(b"verified")
    with pytest.raises(RuntimeError, match="SHA-256"):
        verify_asset_digest(path, None)
    with pytest.raises(RuntimeError, match="SHA-256"):
        verify_asset_digest(path, "sha256:" + "0" * 64)