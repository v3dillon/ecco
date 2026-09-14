"""Exercise real CLI/MCP/relay activity and generic dispatch without an agent SDK."""
import hashlib
import http.server
import json
import os
import pathlib
import socket
import sqlite3
import subprocess
import tempfile
import threading
import time

BINARY = str(pathlib.Path(__file__).resolve().parents[1] / "target/debug/ecco")


def wait_until(predicate, timeout=8):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.05)
    raise AssertionError("condition did not become true")


with tempfile.TemporaryDirectory(prefix="ecco-activity-") as directory:
    root = pathlib.Path(directory)
    user, bins = root / "user", root / "bin"
    user.mkdir()
    bins.mkdir()
    env = {"HOME": str(user), "PATH": f"{bins}:/usr/bin:/bin", "XDG_CONFIG_HOME": str(user / ".config")}

    def executable(path, text):
        path.write_text(text)
        path.chmod(0o700)

    fail_start = root / "fail-start"
    executable(bins / "systemctl", f'''#!/bin/sh
case "$2" in
  is-active|is-enabled) exit 1;;
  start) [ ! -f {fail_start} ];;
  *) exit 0;;
esac
''')

    def run(home, *args, check=True):
        result = subprocess.run([BINARY, "--home", str(home), *args], env=env,
                                text=True, capture_output=True, timeout=25)
        if check and result.returncode:
            raise AssertionError((args, result.stderr, result.stdout))
        return result

    activities, reports = {}, []
    fail_upload = threading.Event()
    slow_upload = threading.Event()
    upload_started = threading.Event()
    upload_release = threading.Event()

    class Reporting(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            data = self.rfile.read(int(self.headers["content-length"]))
            if slow_upload.is_set():
                upload_started.set()
                upload_release.wait(8)
            if fail_upload.is_set():
                self.send_response(503)
                self.end_headers()
                self.wfile.write(b"{}")
                return
            assert self.path == "/collector"
            assert not any(name.lower().startswith("x-trace-") for name in self.headers)
            body = json.loads(data)
            assert body["schema"] == "ecco-activity-v1"
            digest = "sha256:" + hashlib.sha256(data).hexdigest()
            if body["type"] == "message":
                activities[digest] = body
            else:
                assert body["type"] == "dispatcher"
                reports.append(body["report"])
            reply = {"accepted": digest}
            self.send_response(200)
            self.end_headers()
            self.wfile.write(json.dumps(reply).encode())

        def log_message(self, *_):
            pass

    service = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Reporting)
    threading.Thread(target=service.serve_forever, daemon=True).start()
    api = f"http://127.0.0.1:{service.server_port}/collector"
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    authority = f"localhost:{port}"
    relay = subprocess.Popen([BINARY, "relay", "--port", str(port), "--data", str(root / "relay"), "--signed"],
                             env={**env, "ECCO_REPORTING_URL": api}, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def relay_ready():
        try:
            with socket.create_connection(("127.0.0.1", port), 0.1):
                return True
        except OSError:
            return False

    def events(addr=None):
        return [body["envelope"] for body in list(activities.values()) if addr is None or body["observer"] == addr]

    def pending(home):
        return list((home / "reporting-outbox").glob("*/*.json"))

    try:
        wait_until(relay_ready)
        alice, bob = root / "alice", root / "bob"
        for name, home in [("alice", alice), ("bob", bob)]:
            run(home, "init", "--name", name, "--relay", f"http://localhost:{port}")
        assert not (user / ".codex").exists()  # init does not install agent hooks
        before = (alice / "identity.json").read_bytes()
        run(alice, "init")
        assert (alice / "identity.json").read_bytes() == before

        # A held request is visible only after trust. Reporting is independent of agent sessions.
        request = json.loads(run(bob, "send", "--to", f"alice@{authority}", "--about", "smoke",
                                 "--kind", "request", "ping").stdout)
        run(alice, "inbox", "--json")
        wait_until(lambda: len(events(f"bob@{authority}")) == 1)
        assert not events(f"alice@{authority}")
        run(alice, "trust", f"bob@{authority}")
        run(alice, "log", "smoke", "--json")
        wait_until(lambda: len(events(f"alice@{authority}")) == 1)
        assert events(f"alice@{authority}")[0]["from"] == f"bob@{authority}"
        hashes = set(activities)
        run(alice, "inbox", "--json")
        run(alice, "reporting", "retry")
        assert set(activities) == hashes  # deterministic per-envelope event bytes

        # A stalled service must not delay a successful send or hold its stdout pipe.
        slow_upload.set()
        start = time.monotonic()
        encrypted = json.loads(run(alice, "send", "--to", f"bob@{authority}", "--about", "private",
                                   "--encrypt", "never-upload-this-plaintext").stdout)
        assert time.monotonic() - start < 3
        assert upload_started.wait(5)
        upload_release.set()
        slow_upload.clear()
        wait_until(lambda: any(e["id"] == encrypted["id"] for e in events()))
        assert "never-upload-this-plaintext" not in json.dumps(activities)
        assert any(e["encrypted"] and e["text"] is None for e in events())

        # MCP uses the same client path; stdout remains JSON-RPC only.
        mcp_input = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {
            "name": "ecco_send", "arguments": {"to": [f"bob@{authority}"], "about": "mcp", "text": "mcp hello"}}}
        result = subprocess.run([BINARY, "--home", str(alice), "mcp"], input=json.dumps(mcp_input) + "\n",
                                env=env, text=True, capture_output=True, timeout=10, check=True)
        response = json.loads(result.stdout)
        assert response["id"] == 1 and "result" in response, response
        wait_until(lambda: any(e["about"] == "mcp" for e in events()))

        handler, calls = root / "adapter", root / "calls"
        executable(handler, f'''#!/usr/bin/python3
import json, os, pathlib, sys
request = json.load(sys.stdin)
assert request["schema"] == "ecco-dispatch-v1" and request["untrusted"] is True
assert os.environ["WORKER_TEST_SETTING"] == "configured"
assert "UNRELATED_SECRET" not in os.environ
pathlib.Path({str(calls)!r}).open("a").write("x")
print(json.dumps({{"kind":"finding","text":"pong","follow_up":"one clarification"}}))
''')
        env["WORKER_TEST_SETTING"] = "configured"
        env["UNRELATED_SECRET"] = "do not inherit"
        args = ["dispatcher", "install", "--handler", str(handler), "--handler-env", "WORKER_TEST_SETTING",
                "--allow", f"bob@{authority}", "--workdir", str(root)]
        fail_start.touch()
        assert run(alice, *args, check=False).returncode != 0
        assert not (alice / "dispatcher/config.json").exists()
        fail_start.unlink()
        run(alice, *args)
        units = list((user / ".config/systemd/user").glob("*.service"))
        assert len(units) == 1
        unit = units[0]
        assert unit.stat().st_mode & 0o777 == 0o600
        previous, config = unit.read_bytes(), (alice / "dispatcher/config.json").read_bytes()
        fail_start.touch()
        assert run(alice, *args, check=False).returncode != 0
        assert unit.read_bytes() == previous and (alice / "dispatcher/config.json").read_bytes() == config
        fail_start.unlink()

        fail_upload.set()
        run(alice, "dispatcher", "run", "--once")
        assert calls.read_text() == "x"
        db = sqlite3.connect(alice / "dispatcher.sqlite")
        assert db.execute("SELECT status FROM jobs").fetchone()[0] == "completed"
        assert pending(alice)
        db.execute("UPDATE jobs SET status='running'")
        db.commit()
        fail_upload.clear()
        run(alice, "dispatcher", "run", "--once")
        assert calls.read_text() == "x"
        messages = json.loads(run(bob, "log", "smoke", "--json").stdout)["messages"]
        assert len(messages) == 3, messages
        assert len([m for m in messages if m["env"]["kind"] == "finding"]) == 1
        assert all(m["env"]["body"]["in_reply_to"] == request["id"]
                   for m in messages if m["env"]["from"].startswith("alice@"))
        assert any(e["state"] == "completed" for report in reports for e in report["events"])
        assert db.execute("SELECT count(*) FROM report_outbox").fetchone()[0] == 0

        run(alice, "reporting", "retry")
        assert run(alice, "traces", "--help", check=False).returncode != 0
        wait_until(lambda: not pending(alice))
        run(alice, "reporting", "disable")
        run(alice, "init")
        assert json.loads((alice / "reporting.json").read_text())["endpoint"] is None
        run(alice, "send", "--to", f"bob@{authority}", "--about", "disabled", "opted out")
        assert not pending(alice)
        assert not any(e["about"] == "disabled" for e in events())
        run(alice, "dispatcher", "uninstall")
        assert not unit.exists() and (alice / "dispatcher.sqlite").exists()
        db.close()
        print("PASS CLI/MCP activity, trusted reads, encrypted redaction, service discovery, background delivery, generic handler, rollback, durable retries, no duplicate replies, opt-out")
    finally:
        upload_release.set()
        relay.terminate()
        relay.wait(timeout=5)
        service.shutdown()
        service.server_close()
