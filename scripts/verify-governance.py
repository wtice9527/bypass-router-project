#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = [
    ROOT / ".hermes.md",
    ROOT / "docs" / "authority-and-memory.md",
    ROOT / "docs" / "decisions" / "0001-four-layer-memory.md",
    ROOT / "README.md",
    ROOT / "SECURITY.md",
]

# Scan project-owned text only. Exclude virtual environments, generated output,
# VCS metadata, caches, and binary/package artifacts.
EXCLUDED_DIRS = {".git", ".venv", "venv", "build", "dist", "__pycache__", ".pytest_cache"}
TEXT_SUFFIXES = {".md", ".py", ".sh", ".bash", ".json", ".yaml", ".yml", ".toml", ".ini", ".service", ".nft", ".tmpl", ".txt"}

SECRET_PATTERNS = {
    "private key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "generic api key assignment": re.compile(r"(?i)\b(?:api[_-]?key|token|password|secret)\s*[:=]\s*['\"]?[A-Za-z0-9_./+\-]{20,}"),
    "subscription credential": re.compile(r"(?i)https?://[^\s'\"]+(?:token|key|auth|password)=[^\s'\"&]{8,}"),
}

# Known-safe documentation placeholders and generic descriptions are allowed.
SAFE_LINE_MARKERS = {
    "API Key、订阅或节点凭据",
    "Token、密码或节点凭据",
    "Token、密码、节点密钥",
    "Token、密码、节点凭据",
    "API Key、客户端流量历史",
}


def iter_text_files():
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in EXCLUDED_DIRS for part in path.relative_to(ROOT).parts):
            continue
        if path.suffix.lower() in TEXT_SUFFIXES or path.name in {"LICENSE", ".gitignore"}:
            yield path


def main() -> int:
    errors: list[str] = []
    for path in REQUIRED:
        if not path.is_file() or path.stat().st_size == 0:
            errors.append(f"缺少必需治理文件：{path.relative_to(ROOT)}")

    context = ROOT / ".hermes.md"
    if context.exists():
        text = context.read_text(encoding="utf-8")
        for phrase in ("权威来源", "生产变更硬约束", "记忆治理", "fail closed"):
            if phrase not in text:
                errors.append(f".hermes.md 缺少强制条款：{phrase}")

    for path in iter_text_files():
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for number, line in enumerate(text.splitlines(), 1):
            if any(marker in line for marker in SAFE_LINE_MARKERS):
                continue
            for name, pattern in SECRET_PATTERNS.items():
                if pattern.search(line):
                    errors.append(f"疑似敏感信息（{name}）：{path.relative_to(ROOT)}:{number}")

    if errors:
        print("治理检查失败：")
        for error in errors:
            print(f"- {error}")
        return 1

    print("治理检查通过")
    print(f"- 必需文件：{len(REQUIRED)} 个")
    print(f"- 已扫描文本文件：{sum(1 for _ in iter_text_files())} 个")
    print("- 项目上下文强制条款：完整")
    print("- 敏感信息扫描：未发现命中")
    return 0


if __name__ == "__main__":
    sys.exit(main())
