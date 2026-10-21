import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from tollgate import redirects
from tollgate.db import Store


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        port = self.server.server_address[1]
        routes = {
            "/r1": (302, {"Location": "/r2"}, b""),
            "/r2": (301, {"Location": f"http://hop3.test:{port}/final"}, b""),
            "/final": (200, {"Content-Type": "text/html"}, b"<html>ok</html>"),
            "/meta": (200, {"Content-Type": "text/html"},
                      b'<meta http-equiv="refresh" content="0; url=/final"><body>wait</body>'),
            "/loop": (302, {"Location": "/loop"}, b""),
            "/dl": (200, {"Content-Type": "application/octet-stream",
                          "Content-Disposition": 'attachment; filename="invoice.exe"'}, b"MZ"),
            "/internal": (302, {"Location": "http://169.254.169.254/latest/meta-data/"}, b""),
            "/js": (302, {"Location": "javascript:alert(1)"}, b""),
            "/jsredir": (200, {"Content-Type": "text/html"}, b"<script>window.location='http://x.test/'</script>"),
        }
        status, headers, body = routes.get(self.path, (404, {}, b"nope"))
        self.send_response(status)
        for k, v in headers.items():
            self.send_header(k, v)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def server():
    srv = HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def lab_resolver(host, port):          # every test hostname "resolves" to the local lab server
    return ["127.0.0.1"]


def run(port, path, **kw):
    kw.setdefault("allow_private", True)
    kw.setdefault("resolver", lab_resolver)
    return redirects.trace_raw(f"http://start.test:{port}{path}", **kw)


# NOTE: lab ports are random, so we temporarily allow them
@pytest.fixture(autouse=True)
def allow_lab_port(server, monkeypatch):
    monkeypatch.setattr(redirects, "ALLOWED_PORTS", {80, 443, server})


def test_follows_chain(server):
    r = run(server, "/r1")
    assert [h.status for h in r.hops] == [302, 301, 200]
    assert r.completed and r.final_url.endswith("/final")
    assert r.hops[0].ip == "127.0.0.1"


def test_meta_refresh(server):
    r = run(server, "/meta")
    assert r.hops[0].kind == "meta-refresh" and r.final_url.endswith("/final")
    assert "TRACE_META_REFRESH" in {f.rule_id for f in redirects.assess(r).findings}


def test_loop_and_hop_limit(server):
    assert run(server, "/loop").reason == "redirect loop"
    assert "hop limit" in run(server, "/r1", max_hops=1).reason


def test_download_detected(server):
    res = redirects.assess(run(server, "/dl"))
    f = {x.rule_id: x for x in res.findings}
    assert f["TRACE_DOWNLOAD"].severity.value == "high"


def test_js_redirect_noted(server):
    assert "TRACE_JS_REDIRECT" in {f.rule_id for f in redirects.assess(run(server, "/jsredir")).findings}


def test_non_web_scheme_stops(server):
    res = redirects.assess(run(server, "/js"))
    assert "TRACE_NONWEB_SCHEME" in {f.rule_id for f in res.findings}


def test_loopback_is_refused_by_default(server):
    r = redirects.trace_raw(f"http://start.test:{server}/r1", resolver=lab_resolver)   # allow_private=False
    assert r.hops[0].blocked and r.hops[0].status is None          # refused before any connection


def test_redirect_into_metadata_address_is_not_followed(server, monkeypatch):
    real = redirects.is_public_ip
    monkeypatch.setattr(redirects, "is_public_ip", lambda ip: ip == "127.0.0.1" or real(ip))  # lab host only
    connections = []
    orig = redirects.socket.create_connection
    monkeypatch.setattr(redirects.socket, "create_connection",
                        lambda addr, *a, **k: (connections.append(addr), orig(addr, *a, **k))[1])

    def resolver(host, port):
        return ["127.0.0.1"] if host == "start.test" else ["169.254.169.254"]

    res = redirects.trace_raw(f"http://start.test:{server}/internal", resolver=resolver)
    assert res.hops[0].status == 302
    assert res.hops[1].blocked and "169.254.169.254" in res.hops[1].blocked
    assert all(host != "169.254.169.254" for host, _ in connections)      # never even connected
    assert "TRACE_INTERNAL_TARGET" in {f.rule_id for f in redirects.assess(res).findings}


def test_public_ip_policy():
    assert not redirects.is_public_ip("127.0.0.1")
    assert not redirects.is_public_ip("10.1.2.3")
    assert not redirects.is_public_ip("169.254.169.254")
    assert not redirects.is_public_ip("100.64.0.1")
    assert not redirects.is_public_ip("::1")
    assert not redirects.is_public_ip("::ffff:127.0.0.1")
    assert redirects.is_public_ip("93.184.216.34")


def test_blocked_internal_hop_is_high():
    res = redirects.TraceResult(start="http://a.test/", hops=[
        redirects.Hop(url="http://a.test/", status=302, location="http://169.254.169.254/"),
        redirects.Hop(url="http://169.254.169.254/", blocked="resolves to non-public address 169.254.169.254")])
    out = redirects.assess(res)
    assert "TRACE_INTERNAL_TARGET" in {f.rule_id for f in out.findings}
    assert out.verdict == "Suspicious"


def test_disallowed_port_and_non_http():
    assert redirects.trace_raw("ftp://x.test/").reason.startswith("only http")
    r = redirects.trace_raw("http://x.test:22/", resolver=lambda h, p: ["93.184.216.34"])
    assert r.hops[0].blocked and "port 22" in r.hops[0].blocked


def test_intel_on_hop_is_decisive():
    store = Store(":memory:")
    store.add_ioc("domain", "hop3.test", family="Demo", source="unit")
    res = redirects.TraceResult(start="http://a.test/", hops=[
        redirects.Hop(url="http://a.test/", status=302, location="http://hop3.test/x"),
        redirects.Hop(url="http://hop3.test/x", status=200)], final_url="http://hop3.test/x")
    out = redirects.assess(res, store)
    assert out.verdict == "Malicious"
    assert store.tracked_urls()           # hops are tracked as sightings
