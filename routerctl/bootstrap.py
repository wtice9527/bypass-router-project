from __future__ import annotations

import gzip
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path

import yaml


def select_release_asset_info(assets: list[dict], pattern: str) -> dict | None:
    regex = re.compile(pattern, re.IGNORECASE)
    matches = [asset for asset in assets if regex.search(str(asset.get("name", "")))]
    if len(matches) > 1:
        raise RuntimeError("上游发布中存在多个匹配文件，拒绝选择不明确的二进制")
    return matches[0] if matches else None


def select_release_asset(assets: list[dict], pattern: str) -> str | None:
    asset = select_release_asset_info(assets, pattern)
    return asset.get("browser_download_url") if asset else None


def verify_asset_digest(path: Path, digest: str | None) -> None:
    if not digest or not digest.startswith("sha256:"):
        raise RuntimeError("上游发布文件没有 GitHub SHA-256 digest，拒绝安装")
    expected = digest.split(":", 1)[1].lower()
    actual = hashlib.sha256(path.read_bytes()).hexdigest()
    if actual != expected:
        raise RuntimeError("下载文件 SHA-256 校验失败")


def run(cmd: list[str], timeout: int = 300) -> None:
    result = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=timeout)
    if result.returncode:
        raise RuntimeError(f"命令失败: {' '.join(cmd)}\n{result.stdout[-2000:]}")


def github_release(repo: str, latest: bool = True) -> dict:
    endpoint = f"https://api.github.com/repos/{repo}/releases/latest" if latest else f"https://api.github.com/repos/{repo}/releases"
    req = urllib.request.Request(endpoint, headers={"Accept": "application/vnd.github+json", "User-Agent": "bypass-router-installer"})
    with urllib.request.urlopen(req, timeout=30) as response:
        data = json.load(response)
    return data if isinstance(data, dict) else data[0]


def download(url: str, target: Path) -> None:
    req = urllib.request.Request(url, headers={"User-Agent": "bypass-router-installer"})
    with urllib.request.urlopen(req, timeout=120) as response, target.open("wb") as out:
        shutil.copyfileobj(response, out)


def architecture() -> str:
    machine = platform.machine().lower()
    mapping = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64"}
    if machine not in mapping:
        raise RuntimeError(f"暂不支持架构: {machine}")
    return mapping[machine]


def install_mihomo() -> None:
    arch = architecture()
    release = github_release("MetaCubeX/mihomo")
    asset = select_release_asset_info(release.get("assets", []), rf"mihomo-linux-{arch}-v?\d+\.\d+\.\d+\.gz$")
    if not asset:
        raise RuntimeError("未找到匹配的 Mihomo 发布文件")
    with tempfile.TemporaryDirectory() as td:
        archive = Path(td) / "mihomo.gz"
        binary = Path(td) / "mihomo"
        download(asset["browser_download_url"], archive)
        verify_asset_digest(archive, asset.get("digest"))
        with gzip.open(archive, "rb") as src, binary.open("wb") as dst:
            shutil.copyfileobj(src, dst)
        os.chmod(binary, 0o755)
        shutil.copy2(binary, "/usr/local/bin/mihomo")


def install_mosdns() -> None:
    arch = architecture()
    release = github_release("IrineSistiana/mosdns")
    asset = select_release_asset_info(release.get("assets", []), rf"mosdns-linux-{arch}\.zip$")
    if not asset:
        raise RuntimeError("未找到匹配的 MosDNS 发布文件")
    with tempfile.TemporaryDirectory() as td:
        archive = Path(td) / "mosdns.zip"
        download(asset["browser_download_url"], archive)
        verify_asset_digest(archive, asset.get("digest"))
        run(["unzip", "-q", str(archive), "-d", td])
        candidates = list(Path(td).rglob("mosdns"))
        if not candidates:
            raise RuntimeError("MosDNS 压缩包中没有 mosdns")
        os.chmod(candidates[0], 0o755)
        shutil.copy2(candidates[0], "/usr/local/bin/mosdns")


def install_adguardhome() -> None:
    arch = architecture()
    release = github_release("AdguardTeam/AdGuardHome")
    asset = select_release_asset_info(release.get("assets", []), rf"AdGuardHome_linux_{arch}\.tar\.gz$")
    if not asset:
        raise RuntimeError("未找到匹配的 AdGuard Home 发布文件")
    with tempfile.TemporaryDirectory() as td:
        archive = Path(td) / "adguard.tar.gz"
        download(asset["browser_download_url"], archive)
        verify_asset_digest(archive, asset.get("digest"))
        with tarfile.open(archive, "r:gz") as tar:
            tar.extractall(td, filter="data")
        binary = next(iter(Path(td).rglob("AdGuardHome")), None)
        if not binary or not binary.is_file():
            raise RuntimeError("AdGuard Home 压缩包中没有可执行文件")
        os.chmod(binary, 0o755)
        shutil.copy2(binary, "/usr/local/bin/AdGuardHome")


def install_system_dependencies() -> None:
    run(["apt-get", "update"], timeout=300)
    run([
        "apt-get", "install", "-y", "python3", "python3-venv", "python3-pip",
        "nftables", "iproute2", "curl", "ca-certificates", "unzip",
        "network-manager", "nodejs",
    ], timeout=600)


def install_bootstrap_binaries(config: dict) -> None:
    if config.get("install_dependencies"):
        install_system_dependencies()
    if config.get("install_mihomo") and not shutil.which("mihomo"):
        install_mihomo()
    if config.get("install_mosdns") and not shutil.which("mosdns"):
        install_mosdns()
    if config.get("install_adguardhome") and not shutil.which("AdGuardHome"):
        install_adguardhome()


def should_proxy_subscription_fetch(provider_path: Path = Path("/var/lib/mihomo/providers/main.yaml")) -> bool:
    try:
        data = yaml.safe_load(provider_path.read_text()) or {}
        return bool(data.get("proxies"))
    except Exception:
        return False


def apply_networkmanager(config: dict) -> None:
    if not config.get("manage_network"):
        return
    from .wizard import networkmanager_commands
    for cmd in networkmanager_commands(config):
        run(cmd, timeout=90)
