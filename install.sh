#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
cd "$ROOT_DIR"

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  printf '请使用 root 权限运行：sudo ./install.sh\n' >&2
  exit 1
fi

if [[ ! -r /etc/os-release ]]; then
  printf '无法识别操作系统；当前安装器仅支持 Debian 13。\n' >&2
  exit 1
fi
. /etc/os-release
if [[ ${ID:-} != debian ]]; then
  printf '当前系统为 %s；安装器仅支持 Debian。\n' "${PRETTY_NAME:-unknown}" >&2
  exit 1
fi

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y python3 python3-venv python3-pip ca-certificates curl nftables iproute2 unzip network-manager nodejs

python3 -m venv .venv
.venv/bin/pip install -e .

printf '\n=== Debian 旁路由交互部署向导 ===\n'
printf '安装前请确保具有虚拟机控制台、物理控制台或 Tailscale 带外管理通道。\n\n'
exec .venv/bin/routerctl wizard --install --bootstrap