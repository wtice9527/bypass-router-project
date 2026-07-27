#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SKIP = {".git", ".venv", "build", "dist", "release", "__pycache__"}
ALLOW = {
    "secrets.example.json", "scripts/scan-secrets.py",
    "scripts/verify-governance.py", "scripts/check-secrets.py",
    "tests/test_config.py", "tests/test_lifecycle.py",
}
PATTERNS = {
    "生产旁路由地址": re.compile(r"\b192\.168\.10\.112\b"),
    "生产 Tailscale 地址": re.compile(r"\b100\.97\.58\.127\b"),
    "UUID": re.compile(r"\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}\b"),
    "URL 凭据": re.compile(r"(?i)https?://[^\s'\"]+(?:token|key|auth|password|subscribe)=[^\s'\"&]{8,}"),
    "私钥": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "疑似长令牌": re.compile(r"(?i)\b(?:api[_-]?key|token|password|secret)\s*[:=]\s*['\"]?[A-Za-z0-9_./+\-]{24,}"),
}

findings = []
for path in ROOT.rglob("*"):
    rel = str(path.relative_to(ROOT))
    if not path.is_file() or any(part in SKIP for part in path.parts) or rel in ALLOW:
        continue
    try:
        text = path.read_text(errors="strict")
    except (UnicodeDecodeError, OSError):
        continue
    for name, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            if "CHANGE_ME" in match.group(0):
                continue
            line = text.count("\n", 0, match.start()) + 1
            findings.append(f"{path.relative_to(ROOT)}:{line}: {name}")
if findings:
    print("\n".join(findings))
    raise SystemExit(1)
print("敏感信息扫描通过")
