from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

from werkzeug.security import generate_password_hash

from .config import load, load_secrets, public, render_tree

ROOT = Path(__file__).resolve().parents[1]
RUNTIME_STATE = Path("/var/lib/bypass-router-project")
MANIFEST = RUNTIME_STATE / "manifest.json"
BACKUPS = RUNTIME_STATE / "backups"
UNITS = [
    "mihomo.service", "mosdns.service", "adguardhome.service",
    "bypass-router-input-guard.service", "bypass-router-tproxy.service",
    "bypass-router-web.service", "bypass-router-watchdog.timer",
    "bypass-router-provider-update.timer",
]


def run(cmd: list[str], check: bool = True, timeout: int = 120) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"命令失败 ({result.returncode}): {' '.join(cmd)}\n{result.stdout[-2000:]}")
    return result


def sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def copy_file(src: Path, dst: Path, mode: int | None = None) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(src, dst)
    if mode is not None:
        os.chmod(dst, mode)


def prepare_stage(config_path: str, secrets_path: str | None, require_secrets: bool) -> tuple[dict, dict, tempfile.TemporaryDirectory, Path]:
    config = load(config_path)
    secrets = load_secrets(secrets_path, required=require_secrets)
    td = tempfile.TemporaryDirectory(prefix="bypass-router-stage-")
    stage = Path(td.name)
    render_tree(ROOT / "templates", stage / "rendered", config)

    provider = stage / "rootfs/var/lib/mihomo/providers/main.yaml"
    provider.parent.mkdir(parents=True, exist_ok=True)
    provider.write_text("proxies: []\n")
    os.chmod(provider, 0o600)

    for directory in (
        stage / "rootfs/var/lib/mihomo/subscriptions",
        stage / "rootfs/var/lib/mihomo/subscription-candidates",
        stage / "rootfs/var/lib/mihomo/subscription-backups",
        stage / "rootfs/var/lib/mihomo/rule-backups",
        stage / "rootfs/var/lib/mihomo/preferred-backups",
        stage / "rootfs/var/lib/adguardhome",
        stage / "rootfs/var/log/bypass-router",
        stage / "rootfs/var/lib/bypass-router-watchdog",
        stage / "rootfs/run/bypass-router-web",
        stage / "rootfs/run/bypass-router-watchdog",
    ):
        directory.mkdir(parents=True, exist_ok=True)

    web = stage / "rootfs/opt/bypass-router-web"
    shutil.copytree(ROOT / "assets/web", web)
    scripts = stage / "rootfs/usr/local/sbin"
    scripts.mkdir(parents=True, exist_ok=True)
    for src in (ROOT / "assets/scripts").iterdir():
        if src.is_file():
            name = "bypass-router-watchdog" if src.name == "bypass-router-watchdog.py" else src.name
            copy_file(src, scripts / name, 0o700)

    for src in (ROOT / "assets/mosdns-geodata").glob("*.txt"):
        copy_file(src, stage / "rendered/mosdns/geodata" / src.name, 0o644)

    if secrets:
        secret_dir = stage / "rootfs/etc/bypass-router/mihomo/secrets"
        secret_dir.mkdir(parents=True, exist_ok=True)
        (secret_dir / "provider-url").write_text(secrets["subscription_url"].strip() + "\n")
        os.chmod(secret_dir / "provider-url", 0o600)
        auth_dir = stage / "rootfs/etc/bypass-router-web"
        auth_dir.mkdir(parents=True, exist_ok=True)
        (auth_dir / "password.hash").write_text(generate_password_hash(secrets["web_admin_password"], method="scrypt") + "\n")
        (auth_dir / "secret-key").write_text(os.urandom(32).hex() + "\n")
        (auth_dir / "auth-generation").write_text(str(int(time.time())) + "\n")
        for p in auth_dir.iterdir():
            os.chmod(p, 0o600)
    return config, secrets, td, stage


def stage_mapping(stage: Path) -> list[tuple[Path, Path, int]]:
    mapping: list[tuple[Path, Path, int]] = []
    sections = {
        "mihomo": Path("etc/bypass-router/mihomo"),
        "mosdns": Path("etc/bypass-router/mosdns"),
        "adguardhome": Path("etc/bypass-router/adguardhome"),
        "nftables": Path("etc/bypass-router/nftables"),
        "scripts": Path("etc/bypass-router/scripts"),
        "web": Path("etc/bypass-router-web"),
        "sysctl": Path("etc/sysctl.d"),
    }
    for section, target in sections.items():
        src_root = stage / "rendered" / section
        if not src_root.exists():
            continue
        for src in src_root.rglob("*"):
            if src.is_file():
                mode = 0o700 if section == "scripts" else (0o600 if section == "web" else 0o644)
                mapping.append((src, target / src.relative_to(src_root), mode))
    systemd = stage / "rendered/systemd"
    for src in systemd.glob("*"):
        if src.is_file():
            mapping.append((src, Path("etc/systemd/system") / src.name, 0o644))
    rootfs = stage / "rootfs"
    if rootfs.exists():
        for src in rootfs.rglob("*"):
            if src.is_file():
                rel = src.relative_to(rootfs)
                mode = src.stat().st_mode & 0o777
                mapping.append((src, rel, mode))
    return mapping


def stage_directories(stage: Path) -> list[tuple[Path, int]]:
    rootfs = stage / "rootfs"
    if not rootfs.exists():
        return []
    result = []
    for src in rootfs.rglob("*"):
        if src.is_dir() and not any(src.iterdir()):
            result.append((src.relative_to(rootfs), 0o700 if str(src.relative_to(rootfs)).startswith(("var/lib", "run")) else 0o755))
    return result


def validate_stage(config_path: str, secrets_path: str | None = None) -> None:
    config, _, td, stage = prepare_stage(config_path, secrets_path, False)
    try:
        rendered = stage / "rendered"
        for nft in (rendered / "nftables").glob("*.nft"):
            run(["nft", "-c", "-f", str(nft)])
        mihomo = shutil.which("mihomo") or "/usr/local/bin/mihomo"
        if Path(mihomo).exists():
            validation_data = stage / "validation-mihomo"
            validation_data.mkdir(parents=True, exist_ok=True)
            providers = validation_data / "providers"
            providers.mkdir(parents=True, exist_ok=True)
            (providers / "main.yaml").write_text("proxies: []\n")
            run([mihomo, "-t", "-d", str(validation_data), "-f", str(rendered / "mihomo/config.yaml")])
        mosdns = shutil.which("mosdns") or "/usr/local/bin/mosdns"
        if Path(mosdns).exists():
            run([mosdns, "check", "-c", str(rendered / "mosdns/config.yaml")], check=False)
        for py in [stage / "rootfs/opt/bypass-router-web/app.py", *stage.glob("rootfs/usr/local/sbin/*")]:
            if py.is_file() and py.read_bytes().startswith(b"#!") and (b"python" in py.read_bytes()[:100] or py.suffix == ".py"):
                run([sys.executable, "-m", "py_compile", str(py)])
        node = shutil.which("node")
        if node:
            run([node, "--check", str(stage / "rootfs/opt/bypass-router-web/static/app.js")])
        print("配置和项目静态校验通过")
    finally:
        td.cleanup()


def generate(config_path: str, out: str) -> None:
    config, _, td, stage = prepare_stage(config_path, None, False)
    try:
        target = Path(out)
        if target.exists():
            shutil.rmtree(target)
        target.mkdir(parents=True)
        for src, rel, mode in stage_mapping(stage):
            copy_file(src, target / rel, mode)
        (target / "effective-config.json").write_text(json.dumps(public(config), ensure_ascii=False, indent=2) + "\n")
        print(f"已生成脱敏 rootfs：{target}")
    finally:
        td.cleanup()


def prefix_path(prefix: Path, rel: Path) -> Path:
    return prefix / rel


def backup_existing(prefix: Path, rels: list[Path], version: str) -> Path:
    stamp = time.strftime("%Y%m%d-%H%M%S")
    backup = prefix_path(prefix, BACKUPS.relative_to("/")) / f"{stamp}-{version}"
    serial = 1
    while backup.exists():
        backup = prefix_path(prefix, BACKUPS.relative_to("/")) / f"{stamp}-{version}-{serial}"
        serial += 1
    backup.mkdir(parents=True, exist_ok=False)
    manifest_rel = MANIFEST.relative_to("/")
    if prefix_path(prefix, manifest_rel).exists():
        rels = list(rels) + [manifest_rel]
    meta = []
    for rel in sorted(set(rels)):
        src = prefix_path(prefix, rel)
        if not src.exists() or not src.is_file():
            continue
        dst = backup / "rootfs" / rel
        copy_file(src, dst, src.stat().st_mode & 0o777)
        meta.append(str(rel))
    (backup / "files.json").write_text(json.dumps(meta, ensure_ascii=False, indent=2) + "\n")
    if prefix == Path("/"):
        states = {u: run(["systemctl", "is-enabled", u], False).stdout.strip() for u in UNITS}
        (backup / "units.json").write_text(json.dumps(states, ensure_ascii=False, indent=2) + "\n")
    return backup


def remove_files(prefix: Path, rels: list[Path]) -> None:
    for rel in rels:
        prefix_path(prefix, rel).unlink(missing_ok=True)


def stop_managed_services(prefix: Path) -> None:
    if prefix != Path("/"):
        return
    for unit in (
        "bypass-router-watchdog.timer", "bypass-router-provider-update.timer",
        "bypass-router-tproxy.service", "bypass-router-input-guard.service",
        "bypass-router-web.service", "adguardhome.service", "mosdns.service", "mihomo.service",
    ):
        run(["systemctl", "stop", unit], False)


def write_manifest(prefix: Path, version: str, entries: list[dict], backup: Path | None) -> None:
    path = prefix_path(prefix, MANIFEST.relative_to("/"))
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({
        "version": version,
        "installed_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "backup": str(backup) if backup else None,
        "files": entries,
    }, ensure_ascii=False, indent=2) + "\n")


def current_manifest(prefix: Path) -> dict:
    path = prefix_path(prefix, MANIFEST.relative_to("/"))
    return json.loads(path.read_text()) if path.exists() else {}


def apply(config_path: str, secrets_path: str, prefix: str, yes: bool, action: str) -> None:
    if not yes:
        raise SystemExit(f"{action} 会写入目标系统，请增加 --yes")
    target_prefix = Path(prefix).resolve()
    config, _, td, stage = prepare_stage(config_path, secrets_path, True)
    version = (ROOT / "VERSION").read_text().strip()
    mapping = stage_mapping(stage)
    directories = stage_directories(stage)
    old = current_manifest(target_prefix)
    old_rels = [Path(x["path"]) for x in old.get("files", [])]
    new_rels = [rel for _, rel, _ in mapping]
    backup = backup_existing(target_prefix, old_rels + new_rels, old.get("version", "unmanaged"))
    installed: list[dict] = []
    try:
        for rel, mode in directories:
            directory = prefix_path(target_prefix, rel)
            directory.mkdir(parents=True, exist_ok=True)
            os.chmod(directory, mode)
        for src, rel, mode in mapping:
            dst = prefix_path(target_prefix, rel)
            copy_file(src, dst, mode)
            installed.append({"path": str(rel), "sha256": sha256(dst), "mode": oct(mode)})
        remove_files(target_prefix, [rel for rel in old_rels if rel not in set(new_rels)])
        if target_prefix == Path("/"):
            env = {
                "DEBIAN_FRONTEND": "noninteractive",
                "PIP_DISABLE_PIP_VERSION_CHECK": "1",
            }
            venv = Path("/opt/bypass-router-web/venv")
            if not venv.exists():
                run([sys.executable, "-m", "venv", str(venv)])
            run([str(venv / "bin/pip"), "install", "-r", "/opt/bypass-router-web/requirements.txt"], timeout=300)
            run(["systemctl", "daemon-reload"])
            run(["sysctl", "--system"])
            for unit in UNITS:
                run(["systemctl", "enable", unit], False)
            for unit in ["mihomo", "mosdns", "adguardhome", "bypass-router-input-guard", "bypass-router-tproxy", "bypass-router-web"]:
                run(["systemctl", "restart", unit])
            run(["systemctl", "start", "bypass-router-watchdog.timer", "bypass-router-provider-update.timer"], False)
            subscription = json.loads(Path(secrets_path).read_text())["subscription_url"]
            preview = run(["/usr/local/sbin/mihomo-subscription-manage", "preview", "--url", subscription])
            token = json.loads(preview.stdout).get("token")
            if not token:
                raise RuntimeError("订阅预检未返回确认令牌")
            run(["/usr/local/sbin/mihomo-subscription-manage", "apply", "--token", token], timeout=120)
        write_manifest(target_prefix, version, installed, backup)
        print(f"{action}完成；版本 {version}；备份 {backup}")
    except Exception:
        stop_managed_services(target_prefix)
        remove_files(target_prefix, [Path(x["path"]) for x in installed])
        restore_backup(target_prefix, backup)
        raise
    finally:
        td.cleanup()


def restore_backup(prefix: Path, backup: Path) -> None:
    backed = set(json.loads((backup / "files.json").read_text())) if (backup / "files.json").exists() else set()
    current = current_manifest(prefix)
    for entry in current.get("files", []):
        if entry["path"] not in backed:
            prefix_path(prefix, Path(entry["path"])).unlink(missing_ok=True)
    rootfs = backup / "rootfs"
    if rootfs.exists():
        for src in rootfs.rglob("*"):
            if src.is_file():
                copy_file(src, prefix_path(prefix, src.relative_to(rootfs)), src.stat().st_mode & 0o777)
    if prefix == Path("/"):
        run(["systemctl", "daemon-reload"], False)
        units_file = backup / "units.json"
        if units_file.exists():
            states = json.loads(units_file.read_text())
            for unit, state in states.items():
                if state in {"enabled", "enabled-runtime", "linked", "linked-runtime", "alias"}:
                    run(["systemctl", "enable", unit], False)
                else:
                    run(["systemctl", "disable", unit], False)
        for unit in ["mihomo", "mosdns", "adguardhome", "bypass-router-input-guard", "bypass-router-tproxy", "bypass-router-web"]:
            run(["systemctl", "restart", unit], False)


def rollback(prefix: str, backup: str | None, yes: bool) -> None:
    if not yes:
        raise SystemExit("回滚会覆盖已安装文件，请增加 --yes")
    target = Path(prefix).resolve()
    if backup:
        selected = Path(backup)
    else:
        manifest_backup = current_manifest(target).get("backup")
        if manifest_backup and Path(manifest_backup).exists():
            selected = Path(manifest_backup)
        else:
            candidates = sorted(prefix_path(target, BACKUPS.relative_to("/")).glob("*"), key=lambda p: p.stat().st_mtime)
            if not candidates:
                raise SystemExit("没有可用备份")
            selected = candidates[-1]
    restore_backup(target, selected)
    print("已从备份恢复：", selected)


def uninstall(prefix: str, yes: bool) -> None:
    if not yes:
        raise SystemExit("卸载会删除项目管理的文件，请增加 --yes")
    target = Path(prefix).resolve()
    manifest = current_manifest(target)
    if not manifest:
        raise SystemExit("未找到安装 manifest")
    backup = backup_existing(target, [Path(x["path"]) for x in manifest.get("files", [])], manifest.get("version", "unknown"))
    if target == Path("/"):
        for unit in reversed(UNITS):
            run(["systemctl", "disable", "--now", unit], False)
    for entry in manifest.get("files", []):
        prefix_path(target, Path(entry["path"])).unlink(missing_ok=True)
    prefix_path(target, MANIFEST.relative_to("/")).unlink(missing_ok=True)
    print("卸载完成；恢复点：", backup)


def status(prefix: str) -> None:
    target = Path(prefix).resolve()
    manifest = current_manifest(target)
    if not manifest:
        print(json.dumps({"installed": False}, ensure_ascii=False))
        return
    drift = []
    for entry in manifest.get("files", []):
        path = prefix_path(target, Path(entry["path"]))
        if not path.exists() or sha256(path) != entry["sha256"]:
            drift.append(entry["path"])
    data = {"installed": True, "version": manifest.get("version"), "drift": drift}
    if target == Path("/"):
        data["services"] = {u: run(["systemctl", "is-active", u], False).stdout.strip() for u in UNITS}
    print(json.dumps(data, ensure_ascii=False, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser(prog="routerctl")
    sub = parser.add_subparsers(dest="cmd", required=True)
    for name in ("validate", "generate"):
        p = sub.add_parser(name)
        p.add_argument("-c", "--config", default="config.json")
        if name == "validate":
            p.add_argument("-s", "--secrets")
        else:
            p.add_argument("-o", "--output", default="build/rootfs")
    p = sub.add_parser("wizard")
    p.add_argument("-c", "--config", default="config.json")
    p.add_argument("-s", "--secrets", default="secrets.json")
    p.add_argument("--install", action="store_true")
    p.add_argument("--bootstrap", action="store_true", help="安装缺失的系统依赖和核心二进制")
    p.add_argument("--prefix", default="/")
    p.add_argument("--yes", action="store_true")
    for name in ("install", "upgrade"):
        p = sub.add_parser(name)
        p.add_argument("-c", "--config", default="config.json")
        p.add_argument("-s", "--secrets", required=True)
        p.add_argument("--prefix", default="/")
        p.add_argument("--yes", action="store_true")
    p = sub.add_parser("rollback")
    p.add_argument("--prefix", default="/")
    p.add_argument("--backup")
    p.add_argument("--yes", action="store_true")
    p = sub.add_parser("uninstall")
    p.add_argument("--prefix", default="/")
    p.add_argument("--yes", action="store_true")
    p = sub.add_parser("status")
    p.add_argument("--prefix", default="/")
    args = parser.parse_args()
    if args.cmd == "validate":
        validate_stage(args.config, args.secrets)
    elif args.cmd == "generate":
        generate(args.config, args.output)
    elif args.cmd in {"install", "upgrade"}:
        apply(args.config, args.secrets, args.prefix, args.yes, args.cmd)
    elif args.cmd == "rollback":
        rollback(args.prefix, args.backup, args.yes)
    elif args.cmd == "uninstall":
        uninstall(args.prefix, args.yes)
    elif args.cmd == "status":
        status(args.prefix)
    elif args.cmd == "wizard":
        from .wizard import run_wizard
        run_wizard(args.config, args.secrets, args.install, args.yes, args.prefix, args.bootstrap)


if __name__ == "__main__":
    main()
