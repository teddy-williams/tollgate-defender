import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs

import pytest

from tollgate import intel
from tollgate.db import Store

H1, H2 = "a" * 64, "b" * 64
SEEN: list = []


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _reply(self, code, payload, ctype="application/json"):
        body = payload if isinstance(payload, bytes) else payload.encode() if isinstance(payload, str) else json.dumps(payload).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _route(self, body):
        if self.headers.get("Auth-Key") != "k3y" and self.path != "/lines":
            return self._reply(401, {"query_status": "unknown_auth_key"})
        SEEN.append((self.command, self.path, body))
        if self.path == "/urlhaus":
            return self._reply(200, {"query_status": "ok", "urls": [{"url": "http://bad.example/a.exe"}, {"url": "http://bad2.example/b"}, {"url": ""}]})
        if self.path == "/bazaar":
            return self._reply(200, {"query_status": "ok", "data": [{"sha256_hash": H1, "signature": "Emotet"}, {"sha256_hash": H2, "signature": None}, {"sha256_hash": "short"}]})
        if self.path == "/threatfox":
            return self._reply(200, {"query_status": "ok", "data": [
                {"ioc": "evil3.example", "ioc_type": "domain", "malware_printable": "Qakbot", "confidence_level": 100},
                {"ioc": "1.2.3.4:443", "ioc_type": "ip:port", "malware_printable": "Low", "confidence_level": 50},
                {"ioc": "5.6.7.8:80", "ioc_type": "ip:port", "malware_printable": "Mid", "confidence_level": 90},
                {"ioc": "http://x.example/p", "ioc_type": "url", "malware_printable": "Y", "confidence_level": 90},
                {"ioc": "weird", "ioc_type": "unknown_type", "confidence_level": 100}]})
        if self.path == "/lines":
            return self._reply(200, f"# comment\n{H1}\n", "text/plain")
        if self.path == "/badstatus":
            return self._reply(200, {"query_status": "unknown_auth_key"})
        if self.path == "/html":
            return self._reply(200, b"<html>oops</html>", "text/html")
        return self._reply(404, {})

    def do_GET(self):
        self._route(b"")

    def do_POST(self):
        self._route(self.rfile.read(int(self.headers.get("Content-Length", "0"))))


@pytest.fixture(scope="module")
def server():
    srv = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def write_config(tmp_path, base, **overrides):
    feeds = [
        {"name": "urlhaus", "url": base + "/urlhaus", "headers_from_env": {"Auth-Key": "TEST_KEY"}, "format": "json", "json_path": "urls",
         "json_field": "url", "type": "url", "source": "URLhaus", "severity": "high"},
        {"name": "bazaar", "url": base + "/bazaar", "body": {"query": "get_recent", "selector": "time"}, "body_format": "form",
         "headers_from_env": {"Auth-Key": "TEST_KEY"}, "format": "json", "json_path": "data", "json_field": "sha256_hash",
         "family_field": "signature", "type": "sha256", "source": "Bazaar", "severity": "critical"},
        {"name": "threatfox", "url": base + "/threatfox", "body": {"query": "get_iocs", "days": 1}, "body_format": "json",
         "headers_from_env": {"Auth-Key": "TEST_KEY"}, "format": "threatfox", "min_confidence": 75, "source": "ThreatFox", "severity": "high"},
    ]
    feeds[0].update(overrides)
    path = tmp_path / "feeds.json"
    path.write_text(json.dumps({"feeds": feeds}))
    return str(path)


def test_abusech_style_feeds_import_with_key(server, tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_KEY", "k3y")
    SEEN.clear()
    store = Store(":memory:")
    results = intel.fetch_feeds(store, write_config(tmp_path, server), allow_insecure=True)
    by = {r["feed"]: r for r in results}
    assert by["urlhaus"] == {"feed": "urlhaus", "records": 2, "added": 2, "updated": 0, "invalid": 0}
    assert by["bazaar"]["added"] == 2 and by["bazaar"]["invalid"] == 1                       # "short" is not a hash
    assert by["threatfox"]["added"] == 3                                                    # confidence floor + unknown type dropped
    assert store.lookup_ioc("sha256", H1)["family"] == "Emotet" and store.lookup_ioc("sha256", H1)["severity"] == "critical"
    assert store.lookup_ioc("url", "http://bad.example/a.exe")["severity"] == "high"
    assert store.lookup_ioc("ip", "5.6.7.8")["family"] == "Mid" and store.lookup_ioc("ip", "1.2.3.4") is None
    assert store.lookup_ioc("domain", "evil3.example")["source"] == "ThreatFox"
    bodies = {path: body for _, path, body in SEEN}
    assert parse_qs(bodies["/bazaar"].decode()) == {"query": ["get_recent"], "selector": ["time"]}   # form POST
    assert json.loads(bodies["/threatfox"]) == {"query": "get_iocs", "days": 1}                       # JSON POST
    assert [m for m, p, _ in SEEN if p == "/urlhaus"] == ["GET"] and store.stats()["last_update"]["source"] == "ThreatFox"


def test_missing_or_wrong_key_gives_actionable_errors(server, tmp_path, monkeypatch):
    monkeypatch.delenv("TEST_KEY", raising=False)
    store = Store(":memory:")
    res = intel.fetch_feeds(store, write_config(tmp_path, server), allow_insecure=True)
    assert all("is not set" in r["error"] and "TEST_KEY" in r["error"] for r in res)
    monkeypatch.setenv("TEST_KEY", "wrong")
    res = intel.fetch_feeds(store, write_config(tmp_path, server), allow_insecure=True)
    assert all("401" in r["error"] and "API key" in r["error"] for r in res) and store.stats()["iocs_total"] == 0


def test_bad_feed_does_not_stop_others_and_https_is_enforced(server, tmp_path, monkeypatch):
    monkeypatch.setenv("TEST_KEY", "k3y")
    cfg = write_config(tmp_path, server, url=server + "/badstatus")
    res = intel.fetch_feeds(Store(":memory:"), cfg, allow_insecure=True)
    assert "unknown_auth_key" in res[0]["error"] and "check the API key" in res[0]["error"] and res[1]["added"] == 2
    res = intel.fetch_feeds(Store(":memory:"), write_config(tmp_path, server, url=server + "/html"), allow_insecure=True)
    assert "did not return JSON" in res[0]["error"]
    res = intel.fetch_feeds(Store(":memory:"), write_config(tmp_path, "http://example.org"))        # plain http refused
    assert all(r["error"] == "only https:// feeds are allowed" for r in res)


def test_plain_list_feed_still_works(server, tmp_path):
    cfg = tmp_path / "f.json"
    cfg.write_text(json.dumps({"feeds": [{"name": "lines", "url": server + "/lines", "type": "sha256", "family": "F", "severity": "critical"}]}))
    store = Store(":memory:")
    assert intel.fetch_feeds(store, str(cfg), allow_insecure=True)[0]["added"] == 1 and store.lookup_ioc("sha256", H1)["family"] == "F"
