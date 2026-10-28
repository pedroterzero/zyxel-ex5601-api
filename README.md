# zyxel-ex5601-api

A small Python client and CLI for the web API of the **Zyxel EX5601-T1**, the
fibre/DSL router Odido ships in the Netherlands (also known as the T-56). It
logs in the same way the router's web GUI does, so anything the GUI can read or
change can be scripted, with no browser needed.

> Not affiliated with Zyxel or Odido. Use it on your own router. Write commands
> change real settings; read the warnings below first.

## What it can do

```
zyxel_api.py get <oid>                   raw settings object (JSON), e.g. get lanhosts
zyxel_api.py port-forwards               list NAT port forwards
zyxel_api.py upnp [on|off]               show or set UPnP (and UPnP NAT-T)
zyxel_api.py static-dhcp                 list DHCP reservations
zyxel_api.py add-static-dhcp <MAC> <IP>  add a DHCP reservation
zyxel_api.py delete-static-dhcp <MAC>    remove a DHCP reservation
zyxel_api.py wifi5g [<CH> <BW> [--apply]]  show or set a fixed 5 GHz channel/bandwidth
zyxel_api.py reboot --yes                reboot the router
zyxel_api.py show-cert                   show the router's TLS certificate
zyxel_api.py trust-cert <SHA256>         pin the router's certificate
```

It also works as a library:

```python
import zyxel_api as zx

z = zx.Zyxel()
z.login()
hosts = zx.dal_objects(z, "lanhosts")      # connected devices
forwards = zx.dal_objects(z, "nat")
z.logout()
```

## Setup

Requires Python 3.9+ and two packages:

```
pip install requests cryptography
```

1. Put the router's admin password in a file only you can read (it's on the
   sticker on the router unless you changed it):
   ```
   mkdir -p ~/.config/zyxel
   printf '%s' 'YOUR-PASSWORD' > ~/.config/zyxel/password
   chmod 600 ~/.config/zyxel/password
   ```
2. If your router isn't at `192.168.1.1`, set `ZYXEL_HOST`:
   `export ZYXEL_HOST=192.168.2.1`
3. Pin the router's certificate. The router uses a self-signed certificate, so
   instead of a certificate authority the client accepts exactly one
   certificate, identified by its SHA-256 fingerprint:
   ```
   python3 zyxel_api.py show-cert
   ```
   Open `https://<router>` in a browser **on another device**, look at the
   certificate's SHA-256 fingerprint, and if it matches:
   ```
   python3 zyxel_api.py trust-cert <fingerprint>
   ```
   Until a pin exists, no command that logs in will run. If the certificate
   ever changes (factory reset, firmware update), the client stops before
   sending anything and explains how to check and re-pin.

Configuration is via environment variables: `ZYXEL_HOST`, `ZYXEL_USER`
(default `admin`), `ZYXEL_PASSWORD_FILE` (default `~/.config/zyxel/password`),
`ZYXEL_PIN_FILE` (default `~/.config/zyxel/cert_pin`) or `ZYXEL_CERT_SHA256`.

## Safety notes

- **Login is tried once per run.** The router locks the account after a few
  wrong passwords, so the client never retries a failed login.
- **The password is never printed.** The `wlan` object contains your Wi-Fi
  password in plain text; be careful with `get wlan` output.
- **`wifi5g --apply` restarts the 5 GHz radio** (devices reconnect within about
  a minute). Without `--apply` it's a dry run. It re-sends the router's own
  current Wi-Fi settings with only channel and bandwidth changed, and checks
  afterwards that nothing else changed.
- **Changing WPS restarts the 2.4 GHz radio.** The GUI notes that enabling
  WPS turns UPnP back on.
- `reboot` needs `--yes`.

## Settings objects ("DAL oids")

The GUI reads and writes settings through `/cgi-bin/DAL?oid=<name>`. These were
verified on an EX5601-T1 with firmware V5.70(ACEA.0)T56C:

| oid | contents | writes |
|---|---|---|
| `status` | WAN/LAN overview, public IP, firmware version | – |
| `lanhosts` | connected devices | – |
| `nat` | port forwards | `z.delete("nat", Index)`, `z.post("nat", obj)` |
| `lanadv` | UPnP (`UPnPEnable`, `NATTEnable`) | `z.put` the whole object |
| `wps` | WPS per band (`Object[0]` 2.4 GHz, `[1]` 5 GHz) | `z.put` one band's object |
| `user_account` | admin account, `RemoteAccessPrivilege` (`LAN` / `LAN,WAN`) | `z.put` |
| `static_dhcp` | DHCP reservations | add/delete via the CLI |
| `wlan` | Wi-Fi settings (contains the Wi-Fi password!) | see `wifi5g` |
| `firewall`, `login_privilege`, `lan` | firewall level, account rights, LAN | – |

To change a setting: GET it, change the field, `z.put(oid, obj)`, then GET it
again to check. Each write returns a new session key, which the client picks up
automatically.

**Finding the oid behind a GUI page:** an unknown oid still answers
`ZCFG_SUCCESS` with an empty list, so guessing doesn't work, and the GUI loads
some pages lazily, so searching its JavaScript doesn't find every name. The
reliable way is to open the page in a browser with the developer tools'
network tab open (or with Playwright) and look at the `/cgi-bin/DAL?oid=...`
requests it makes.

## How the login works

Read from the router's own GUI code (`/static/js/app.js`, `httpReqSendAndRecv`):

1. `GET /getRSAPublickKey` returns the router's RSA public key.
2. `POST /UserLogin` with `{content, key, iv}`: `content` is the AES-256-CBC
   encrypted login JSON (password base64-encoded), `key` is the random AES key
   (as base64 text) encrypted with the router's RSA key (PKCS#1 v1.5), and `iv`
   is 32 random bytes of which only the first 16 are used. The response
   decrypts to a JSON object containing the `sessionkey`.
3. `/cgi-bin/...` calls send the session key as the `CSRFToken` header; request
   and response bodies are AES-encrypted with the same AES key and a fresh IV.
4. `POST /cgi-bin/UserLogout` ends the session.

The GUI's encryption layer only protects against passive sniffing; TLS (with
the pinned certificate) is what actually protects the connection.

## License

MIT
