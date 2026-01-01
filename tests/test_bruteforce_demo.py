# tests/test_bruteforce_demo.py
import threading
import time
import socket
import urllib.parse
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
from src.pentesting.brute_force import brute_force_http_login


def _get_free_port() -> int:
    # Reserve a local port for the test server
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _SimDeviceHandler(BaseHTTPRequestHandler):
    # Minimal login endpoint; only admin/admin succeeds

    def do_POST(self):
        if self.path != "/login":
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length).decode(errors="ignore")
        params = urllib.parse.parse_qs(body)

        username = params.get("username", [""])[0]
        password = params.get("password", [""])[0]

        if username == "admin" and password == "admin":
            resp = b"Welcome admin"
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
        else:
            self.send_response(401)
            self.end_headers()

    def log_message(self, *_):
        # suppress server logs during tests
        return


@pytest.fixture
def sim_device():
    port = _get_free_port()
    server = HTTPServer(("127.0.0.1", port), _SimDeviceHandler)

    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.05)  # allow server to start

    yield f"http://127.0.0.1:{port}"

    server.shutdown()
    thread.join(timeout=1)


def test_bruteforce_finds_admin_and_stops(sim_device):
    # Verify brute-force stops at first successful login
    target = sim_device.rstrip("/")
    passwords = ["notit", "admin", "other"]

    res = brute_force_http_login(
        f"{target}/login",
        username="admin",
        passwords=passwords,
        stop_on_success=True,
        rate_limit_delay=0.0,
        max_attempts=None,
    )

    # Check result structure
    assert res.get("test") == "brute_force_login"
    assert res.get("target") == f"{target}/login"

    # Should stop after first valid credential
    assert res.get("success_count") == 1
    assert res.get("stopped_early") is True
    assert res.get("attempts_count") == 2

    # Confirm discovered password
    successes = res.get("successes", [])
    assert len(successes) == 1
    assert successes[0]["password"] == "admin"
