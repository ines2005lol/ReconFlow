"""check_lab() tests start a tiny HTTP server on a random local port and point a
Target at it, so they don't depend on Juice Shop running."""

import http.server
import socket
import threading

import pytest

from recon.lab import LabUnreachableError, check_lab
from recon.targets import Target


class _Handler(http.server.BaseHTTPRequestHandler):
    status = 200

    def do_GET(self):
        self.send_response(self.status)
        self.end_headers()

    def log_message(self, *args):  # keep test output quiet
        pass


@pytest.fixture
def server():
    httpd = http.server.HTTPServer(("127.0.0.1", 0), _Handler)  # port 0 = any free port
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd
    httpd.shutdown()


def test_running_server_passes(server):
    check_lab(Target("127.0.0.1", server.server_port))


def test_error_status_still_counts_as_up(server, monkeypatch):
    monkeypatch.setattr(_Handler, "status", 500)
    check_lab(Target("127.0.0.1", server.server_port))


def test_closed_port_raises():
    with socket.socket() as s:  # grab a free port, then close it so nothing listens
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    with pytest.raises(LabUnreachableError, match="docker compose up -d"):
        check_lab(Target("127.0.0.1", port))
