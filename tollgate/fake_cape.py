"""FAKE CAPE server for demos and tests. It executes NOTHING: it returns canned JSON shaped like CAPE's REST API.

  python -m tollgate.fake_cape --port 8090 [--token SECRET]

Upload a file whose name contains "malware" (or whose bytes contain TOLLGATE-FAKE-MALWARE-MARKER) to get the "bad"
report; anything else gets a benign one. Status moves pending -> running -> reported over successive polls.
Never point production at this. Reports carry "_fake": true.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MARKER = b"TOLLGATE-FAKE-MALWARE-MARKER"


def _report(task: dict, task_id: int) -> dict:
    base = {"info": {"id": task_id, "duration": 95, "machine": {"name": "win10-fake"}}, "_fake": True,
            "target": {"file": {"sha256": task["sha256"], "name": task["name"]}}}
    if not task["bad"]:
        return {**base, "malscore": 1.0, "signatures": [{"name": "antivm_checks_available_memory", "description": "Checks available memory", "severity": 1}],
                "behavior": {"processes": [{"process_name": "sample.exe", "process_id": 1234, "parent_id": 800, "command_line": "C:\\Users\\user\\sample.exe"}], "summary": {}},
                "network": {}, "dropped": []}
    drop = hashlib.sha256(b"fake dropped payload for " + task["sha256"].encode()).hexdigest()
    return {**base, "malscore": 9.5, "malfamily": "FakeFamily",
            "signatures": [
                {"name": "injection_createremotethread", "description": "Code injection with CreateRemoteThread in a remote process", "severity": 3, "ttp": ["T1055"], "data": [{}, {}]},
                {"name": "persistence_autorun", "description": "Installs itself for autorun at Windows startup", "severity": 2, "ttp": ["T1547.001"]},
                {"name": "antivm_checks_available_memory", "description": "Checks available memory", "severity": 1}],
            "behavior": {"processes": [{"process_name": "sample.exe", "process_id": 1234, "parent_id": 800, "command_line": "C:\\Users\\user\\sample.exe"},
                                       {"process_name": "cmd.exe", "process_id": 1300, "parent_id": 1234, "command_line": "cmd.exe /c whoami"}],
                         "summary": {"executed_commands": ["cmd.exe /c whoami"], "mutexes": ["Global\\FakeMutex123"]}},
            "network": {"domains": [{"domain": "c2.demo-sandbox.example", "ip": "198.51.100.23"}, {"domain": "time.windows.com", "ip": "10.0.0.2"}],
                        "hosts": [{"ip": "198.51.100.23"}, {"ip": "10.0.0.5"}],
                        "http": [{"host": "c2.demo-sandbox.example", "port": 80, "uri": "http://c2.demo-sandbox.example/gate.php", "method": "POST"}],
                        "dns": [{"request": "c2.demo-sandbox.example", "type": "A", "answers": []}]},
            "dropped": [{"name": "payload.dll", "sha256": drop, "size": 4096, "type": "PE32 executable (DLL)"}],
            "CAPE": {"payloads": [], "configs": [{"FakeFamily": {"C2": ["http://c2.demo-sandbox.example/gate.php"], "Botnet": "demo"}}]},
            "suricata": {"alerts": [{"signature": "FAKE ET MALWARE Demo C2 beacon", "category": "A Network Trojan was detected", "severity": 1}]}}


def make_handler(token: str | None, tasks: dict):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def _send(self, code: int, payload: dict):
            body = json.dumps(payload).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _authorized(self) -> bool:
            if token and self.headers.get("Authorization") != f"Token {token}":
                self._send(401, {"error": True, "error_value": "Authentication credentials were not provided"})
                return False
            return True

        def do_GET(self):
            if not self._authorized():
                return
            if self.path.startswith("/apiv2/cuckoo/status/"):
                return self._send(200, {"error": False, "data": {"fake": True, "tasks": len(tasks)}})
            m = re.match(r"^/apiv2/tasks/(status|get/report)/(\d+)/$", self.path)
            task = tasks.get(int(m.group(2))) if m else None
            if not m or not task:
                return self._send(404, {"error": True, "error_value": "Task not found"})
            if m.group(1) == "status":
                task["polls"] += 1
                return self._send(200, {"error": False, "data": "pending" if task["polls"] == 1 else "running" if task["polls"] == 2 else "reported"})
            return self._send(200, _report(task, int(m.group(2))))

        def do_POST(self):
            if not self._authorized():
                return
            if self.path != "/apiv2/tasks/create/file/":
                return self._send(404, {"error": True, "error_value": "unknown endpoint"})
            raw = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            boundary = (re.search(r"boundary=(.+)$", self.headers.get("Content-Type", "")) or [None, ""])[1].encode()
            name, content = "sample.bin", b""
            for part in raw.split(b"--" + boundary):
                head, _, body = part.partition(b"\r\n\r\n")
                fm = re.search(rb'name="file"; filename="([^"]*)"', head)
                if fm:
                    name, content = fm.group(1).decode("utf-8", "replace"), body[:-2] if body.endswith(b"\r\n") else body
            task_id = len(tasks) + 1
            tasks[task_id] = {"name": name, "sha256": hashlib.sha256(content).hexdigest(), "polls": 0,
                              "bad": "malware" in name.lower() or MARKER in content}
            self._send(200, {"error": False, "data": {"task_ids": [task_id], "message": f"Task ID {task_id} has been submitted"}})
    return Handler


def start(port: int = 0, token: str | None = None, host: str = "127.0.0.1"):
    """Start in a background thread (used by tests). Returns (server, base_url)."""
    server = ThreadingHTTPServer((host, port), make_handler(token, {}))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://{host}:{server.server_address[1]}"


def main() -> None:
    ap = argparse.ArgumentParser(description="FAKE CAPE API for demos and tests. Executes nothing.")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8090)
    ap.add_argument("--token")
    args = ap.parse_args()
    print(f"FAKE CAPE listening on http://{args.host}:{args.port} (canned data only)")
    ThreadingHTTPServer((args.host, args.port), make_handler(args.token, {})).serve_forever()


if __name__ == "__main__":
    main()
