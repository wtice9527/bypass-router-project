from pathlib import Path

ROOT = Path(__file__).parents[1]


def test_dashboard_excludes_unrelated_tailscale_status_and_labels():
    app = (ROOT / "assets/web/app.py").read_text()
    html = (ROOT / "assets/web/static/index.html").read_text()
    assert '"tailscaled"' not in app
    assert 'TAILSCALE' not in html
    assert 'Tailscale和输入防火墙' not in html
    assert '"tailscale_ip"' not in app
    assert '"router_ip"' not in app
    assert '"hostname"' not in app


def test_dashboard_uses_tproxy_packet_counters_without_client_identity():
    html = (ROOT / "assets/web/static/index.html").read_text()
    js = (ROOT / "assets/web/static/app.js").read_text()
    assert '透明代理流量' in html
    assert 'TCP Redirect' in html
    assert 'UDP TProxy' in html
    assert '测试客户端' not in html
    assert '客户端范围' not in html
    assert 'overviewClientScope' not in html
    assert 'overviewClientScope' not in js
    assert 'tpClientScope' not in html
    assert 'tpClientScope' not in js


def test_service_page_does_not_promise_tailscale_management():
    html = (ROOT / "assets/web/static/index.html").read_text()
    assert 'NetworkManager、Tailscale和输入防火墙' not in html
    assert '核心网络服务仅展示状态，不允许网页停用' in html
