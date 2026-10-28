#!/usr/bin/env python3
"""
Browserless client for the Zyxel EX5601-T1 web API (the router Odido ships in the
Netherlands, also sold as T-56). Not affiliated with Zyxel or any ISP.

It speaks the same JSON API as the router's web GUI, so anything the GUI can
read or change can be scripted. The protocol was read from the router's own
GUI code (/static/js/app.js, function httpReqSendAndRecv):

  Transport: HTTPS with the router certificate pinned (CERT_SHA256 below).

  1. GET /getRSAPublickKey                -> {"RSAPublicKey": PEM}
  2. POST /UserLogin  body {content,key,iv}
       content = AES-256-CBC(PKCS7) of the JSON login payload, base64
                 payload: Input_Account, Input_Passwd=base64(password),
                          currLang, RememberPassword, SHA512_password
       key     = RSA-PKCS1v1.5(router pubkey, <AES key as base64 TEXT>), base64
       iv      = 32 random bytes, base64 (CryptoJS only uses the first 16)
     response {content, iv} -> AES-decrypt with the same key -> {sessionkey,..}
  3. /cgi-bin/... calls: header CSRFToken: <sessionkey>; POST/PUT/DELETE
     bodies are AES-encrypted with the login AES key + fresh IV (no RSA key);
     encrypted responses {content, iv} are decrypted the same way. A write
     returns a new sessionkey, which must be used from then on (this client
     does that automatically).
  4. POST /cgi-bin/UserLogout

Usage:
  zyxel_api.py get <oid>                 raw DAL object, e.g. get static_dhcp, get lanhosts
  zyxel_api.py port-forwards             list NAT port forwards
  zyxel_api.py upnp [on|off]             show or set UPnP (and UPnP NAT-T)
  zyxel_api.py static-dhcp               list static leases
  zyxel_api.py add-static-dhcp <MAC> <IP>
  zyxel_api.py delete-static-dhcp <MAC>
  zyxel_api.py reboot --yes
  zyxel_api.py wifi5g                    show 5GHz channel/bandwidth + valid channels
  zyxel_api.py wifi5g <CH> <BW> [--apply]  set fixed 5GHz channel + bandwidth (dry run
                                         without --apply; refuses invalid/DFS-inactive
                                         channels; verifies nothing else changed)
  zyxel_api.py show-cert                certificate the router presents vs the pin
  zyxel_api.py trust-cert <SHA256>       accept a new cert after verifying it elsewhere
                                         (only if it equals what the router presents)

On a certificate mismatch (exit 3) the script prints the presented cert, the
likely causes and the exact steps to verify and re-pin.

Other DAL oids seen in the GUI code: lanhosts, qos_class, ipalias, ... (274
'DAL?oid=' call sites in app.js). Writes: POST adds, PUT edits (with Index),
DELETE takes ?Index=N.

DAL objects verified on an EX5601-T1 (firmware V5.70(ACEA.0)T56C):
  status        WAN/LAN overview: Object[0].WanLanInfo[] (Encapsulation, Status,
                IPv4Address[].IPAddress), DeviceInfo (SoftwareVersion, ...)
  nat           port forwards: Index, Enable, Description, Protocol,
                ExternalPortStart/End, InternalClient, InternalPortStart/End,
                Interface ("" = auto WAN). Delete with z.delete("nat", Index).
  lanadv        UPnP tab: UPnPEnable, NATTEnable (plus STB/TFTP fields).
                PUT the whole object with the flags changed.
  wps           one object per band (Object[0]=2.4GHz, [1]=5GHz): Enable,
                X_ZYXEL_WPS_EnablePBC/EnableStaPin/EnableAPPin. PUT Object[n]
                with Enable changed; this restarts the 2.4GHz radio (clients
                drop for under a minute). The GUI says enabling WPS turns UPnP
                back on.
  user_account  admin account: RemoteAccessPrivilege ("LAN" or "LAN,WAN"),
                AccountRetryTime/LockTime/IdleTime. PUT Object[0] with the
                field changed (no password fields needed).
  login_privilege, firewall (Level_GUI, IPv4/IPv6_Enable, enableDos),
  static_dhcp, lanhosts, lan, wlan (contains the PSK - never print it).
An unknown oid also answers ZCFG_SUCCESS with an empty Object list, so an
empty result does not prove the oid exists. To find the oid behind a GUI
page, drive the page with Playwright and log the /cgi-bin/ requests it makes
(see router_upnp.py); the GUI loads some pages lazily, so grepping app.js
does not find every oid.

Edits: z.put("<oid>", obj) with the object as returned by GET, then re-read
to verify. Each write returns a new session key; Zyxel._cgi picks it up, so
several writes can share one login (older versions of this client did not,
and a second write then failed with HTTP 403).

Configuration (environment variables):
  ZYXEL_HOST           router address (default 192.168.1.1)
  ZYXEL_USER           admin user (default "admin")
  ZYXEL_PASSWORD_FILE  file holding only the password (default ~/.config/zyxel/password,
                       keep it chmod 600); the password is never printed
  ZYXEL_CERT_SHA256 / ZYXEL_PIN_FILE   certificate pin (see below)
Login is attempted exactly once per run; on failure it stops (the router locks
the account after a few wrong passwords).

Certificate pinning: the router uses a self-signed certificate, so it is pinned
by SHA-256 fingerprint instead. On first use run `show-cert`, compare the
fingerprint with what a browser on another device shows for https://<router>,
and accept it with `trust-cert <fingerprint>`. Until a pin exists, nothing that
needs a login runs.
"""

import base64
import json
import os
import sys

import requests
import urllib3
from requests.adapters import HTTPAdapter
from cryptography.hazmat.primitives import padding as sym_padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

HOST = os.environ.get("ZYXEL_HOST", "192.168.1.1")
USER = os.environ.get("ZYXEL_USER", "admin")
PASSWORD_FILE = os.path.expanduser(os.environ.get("ZYXEL_PASSWORD_FILE", "~/.config/zyxel/password"))

# HTTPS with the router's self-signed certificate pinned by SHA-256 fingerprint.
# The cert has no IP SAN and no CA, so normal verification can't work; the pin
# replaces it and is stricter: any other certificate is refused.
# Pin source, first match wins: env ZYXEL_CERT_SHA256 > PIN_FILE (written by
# `trust-cert`). Every router has its own certificate, so there is no default:
# without a pin, commands that log in refuse to run. On a mismatch the script
# explains what to do.
PIN_FILE = os.path.expanduser(os.environ.get("ZYXEL_PIN_FILE", "~/.config/zyxel/cert_pin"))


def _norm_fp(fp: str) -> str:
    h = fp.replace(":", "").replace(" ", "").upper()
    return ":".join(h[i:i + 2] for i in range(0, len(h), 2))


def load_pin():
    if os.environ.get("ZYXEL_CERT_SHA256"):
        return _norm_fp(os.environ["ZYXEL_CERT_SHA256"]), "env ZYXEL_CERT_SHA256"
    if os.path.exists(PIN_FILE):
        with open(PIN_FILE) as f:
            return _norm_fp(f.read().strip()), PIN_FILE
    return None, "no pin"


CERT_SHA256, PIN_SOURCE = load_pin()


def presented_cert():
    """Fetch (without trusting) the certificate the router presents right now."""
    import socket
    import ssl
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((HOST, 443), timeout=10) as sock, ctx.wrap_socket(sock) as tls:
        der = tls.getpeercert(binary_form=True)
    cert = x509.load_der_x509_certificate(der)
    return _norm_fp(cert.fingerprint(hashes.SHA256()).hex()), cert


def describe_cert(fp, cert) -> str:
    return (f"  presented: {fp}\n"
            f"  subject  : {cert.subject.rfc4514_string()}\n"
            f"  issuer   : {cert.issuer.rfc4514_string()}\n"
            f"  valid    : {cert.not_valid_before:%Y-%m-%d} .. {cert.not_valid_after:%Y-%m-%d}")


def explain_pin_mismatch():
    try:
        fp, cert = presented_cert()
        details = describe_cert(fp, cert)
    except Exception as e:  # noqa: BLE001 - diagnostics only
        fp, details = None, f"  (could not read the presented certificate: {e})"
    print(f"""
TLS PIN CHECK FAILED - nothing was sent to the router (no login attempted).

  pinned   : {CERT_SHA256}   [{PIN_SOURCE}]
{details}

Why this can happen:
  - EXPECTED: the router was factory-reset, re-flashed or got a firmware update
    that generated a new certificate.
  - NOT EXPECTED: something on the network is intercepting traffic to {HOST}.
    If the router hasn't been reset or updated recently, stop here and find out why.

What to do:
  1. Check whether there is an innocent explanation: a recent firmware update
     (ISPs push these), a factory reset, or a replaced router.
  2. Verify the fingerprint independently, NOT with this script: on another device,
     ideally connected by cable, open https://{HOST} in a browser, click the padlock /
     "not secure" warning > certificate > SHA-256 fingerprint, and compare it with
     'presented' above.
  3. Only if they match, accept it:
       {os.path.basename(sys.argv[0])} trust-cert {fp or '<SHA-256 fingerprint>'}
     (stores the new pin in {PIN_FILE})
""")


def trust_cert(fingerprint: str) -> int:
    want = _norm_fp(fingerprint)
    fp, cert = presented_cert()
    if fp != want:
        print(f"Refused: the router presents\n  {fp}\nnot the fingerprint you gave\n  {want}\nNothing changed.")
        return 1
    os.makedirs(os.path.dirname(PIN_FILE), exist_ok=True)
    with open(PIN_FILE, "w") as f:
        f.write(fp + "\n")
    print(f"Pinned the router certificate in {PIN_FILE}:\n{describe_cert(fp, cert)}")
    return 0


class PinnedCertAdapter(HTTPAdapter):
    """Accept exactly one certificate (by fingerprint) instead of CA + hostname checks."""

    def __init__(self, fingerprint: str, **kwargs):
        self.fingerprint = fingerprint.replace(":", "").lower()
        super().__init__(**kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs["assert_fingerprint"] = self.fingerprint
        return super().init_poolmanager(*args, **kwargs)


# verify=False only switches off CA/hostname checking (impossible for this cert);
# the fingerprint assertion above still runs on every connection.
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode()


def aes_encrypt(plaintext: str, key_b64: str, iv_b64: str) -> str:
    padder = sym_padding.PKCS7(128).padder()
    data = padder.update(plaintext.encode()) + padder.finalize()
    enc = Cipher(algorithms.AES(base64.b64decode(key_b64)), modes.CBC(base64.b64decode(iv_b64)[:16])).encryptor()
    return _b64(enc.update(data) + enc.finalize())


def aes_decrypt(content_b64: str, key_b64: str, iv_b64: str) -> str:
    dec = Cipher(algorithms.AES(base64.b64decode(key_b64)), modes.CBC(base64.b64decode(iv_b64)[:16])).decryptor()
    data = dec.update(base64.b64decode(content_b64)) + dec.finalize()
    unpadder = sym_padding.PKCS7(128).unpadder()
    return (unpadder.update(data) + unpadder.finalize()).decode()


class LoginFailed(Exception):
    pass


class Zyxel:
    def __init__(self):
        self.base = f"https://{HOST}"
        self.s = requests.Session()
        self.s.mount("https://", PinnedCertAdapter(CERT_SHA256))
        self.s.mount("http://", HTTPAdapter(max_retries=0))  # never used; base is https
        self.s.verify = False
        self.s.headers["If-Modified-Since"] = "Thu, 01 Jun 1970 00:00:00 GMT"
        self.aes_key = None
        self.session_key = None

    def _decode(self, r: requests.Response):
        try:
            body = r.json()
        except ValueError:
            return r.text
        if isinstance(body, dict) and body.get("content") and body.get("iv"):
            return json.loads(aes_decrypt(body["content"], self.aes_key, body["iv"]))
        return body

    def login(self):
        pem = self.s.get(f"{self.base}/getRSAPublickKey", timeout=15).json()["RSAPublicKey"]
        if "BEGIN" not in pem:
            pem = "-----BEGIN PUBLIC KEY-----\n" + pem + "\n-----END PUBLIC KEY-----\n"
        rsa = serialization.load_pem_public_key(pem.encode())

        with open(PASSWORD_FILE) as f:
            password = f.read().strip()
        payload = json.dumps({
            "Input_Account": USER,
            "Input_Passwd": _b64(password.encode()),
            "currLang": "en",
            "RememberPassword": 0,
            "SHA512_password": False,
        })
        del password

        self.aes_key = _b64(os.urandom(32))
        iv = _b64(os.urandom(32))
        body = {
            "content": aes_encrypt(payload, self.aes_key, iv),
            "key": _b64(rsa.encrypt(self.aes_key.encode(), asym_padding.PKCS1v15())),
            "iv": iv,
        }
        r = self.s.post(f"{self.base}/UserLogin", data=json.dumps(body), timeout=15)
        result = self._decode(r)
        if r.status_code != 200 or not isinstance(result, dict) or not result.get("sessionkey"):
            msg = result.get("result") if isinstance(result, dict) else str(result)[:120]
            raise LoginFailed(f"HTTP {r.status_code}: {msg}")
        self.session_key = str(result["sessionkey"])
        return result

    def logout(self):
        if self.session_key:
            self.s.post(f"{self.base}/cgi-bin/UserLogout", headers={"CSRFToken": self.session_key}, timeout=15)
            self.session_key = None

    def _cgi(self, method: str, path: str, obj=None, timeout: int = 30):
        url = f"{self.base}/cgi-bin/{path}"
        headers = {"CSRFToken": self.session_key}
        data = None
        if obj is not None and method in ("POST", "PUT"):
            iv = _b64(os.urandom(32))
            data = json.dumps({"content": aes_encrypt(json.dumps(obj), self.aes_key, iv), "iv": iv, "key": ""})
        r = self.s.request(method, url, headers=headers, data=data, timeout=timeout)
        result = self._decode(r)
        # Writes return a new session key; the old one is refused from then on.
        if isinstance(result, dict) and result.get("sessionkey"):
            self.session_key = str(result["sessionkey"])
        return r.status_code, result

    def get(self, oid: str):
        return self._cgi("GET", f"DAL?oid={oid}")

    def post(self, oid: str, obj: dict):
        return self._cgi("POST", f"DAL?oid={oid}", obj)

    def put(self, oid: str, obj: dict, timeout: int = 90):
        return self._cgi("PUT", f"DAL?oid={oid}", obj, timeout=timeout)

    def delete(self, oid: str, index: int):
        return self._cgi("DELETE", f"DAL?oid={oid}&Index={index}")


def dal_objects(z, oid: str) -> list:
    """GET a DAL object and return its Object list, raising on any error."""
    status, data = z.get(oid)
    if status != 200 or not isinstance(data, dict) or data.get("result") != "ZCFG_SUCCESS":
        raise RuntimeError(f"reading {oid} failed: HTTP {status} {data if not isinstance(data, dict) else data.get('result')}")
    return data["Object"]


def cmd_upnp(z, args) -> int:
    """Show or set UPnP + UPnP NAT-T (GUI: Network Setting > Home Networking > UPnP)."""
    cur = dal_objects(z, "lanadv")[0]
    print(f"UPnP: {'on' if cur['UPnPEnable'] else 'off'}, UPnP NAT-T: {'on' if cur['NATTEnable'] else 'off'}")
    if not args:
        return 0
    if args[0] not in ("on", "off"):
        raise ValueError("usage: upnp [on|off]")
    want = args[0] == "on"
    if cur["UPnPEnable"] == want and cur["NATTEnable"] == want:
        print("  already set - nothing to do")
        return 0
    new = dict(cur, UPnPEnable=want, NATTEnable=want)
    status, res = z.put("lanadv", new)
    print(f"  PUT lanadv: HTTP {status} {res.get('result') if isinstance(res, dict) else res}")
    after = dal_objects(z, "lanadv")[0]
    ok = after["UPnPEnable"] == want and after["NATTEnable"] == want
    print(f"  read-back: UPnP {'on' if after['UPnPEnable'] else 'off'}, NAT-T {'on' if after['NATTEnable'] else 'off'}")
    return 0 if ok else 1


def static_dhcp_list(z):
    status, data = z.get("static_dhcp")
    if status != 200 or data.get("result") != "ZCFG_SUCCESS":
        raise RuntimeError(f"reading static_dhcp failed: HTTP {status} {data}")
    return data["Object"]


def add_static_dhcp(z, mac: str, ip: str):
    """Same payload and checks as the GUI's StaticDHCPConfig dialog."""
    import ipaddress
    mac = mac.lower()
    octets = mac.split(":")
    if len(octets) != 6 or any(len(o) != 2 for o in octets) or int(octets[0], 16) & 1:
        raise ValueError(f"invalid or multicast MAC: {mac}")
    if ipaddress.ip_address(ip) not in ipaddress.ip_network(f"{HOST}/24", strict=False) or ip == HOST \
            or ip.endswith((".0", ".255")):
        raise ValueError(f"IP {ip} not a usable LAN address")
    for e in static_dhcp_list(z):
        if e["MACAddr"].lower() == mac or e["IPAddr"] == ip:
            raise ValueError(f"already reserved: #{e['Index']} {e['MACAddr']} -> {e['IPAddr']}")
    obj = {"Index": 0, "BrWan": "Default", "Enable": True, "MACAddr": mac, "IPAddr": ip}
    return z.post("static_dhcp", obj)


def delete_static_dhcp(z, mac: str):
    mac = mac.lower()
    match = [e for e in static_dhcp_list(z) if e["MACAddr"].lower() == mac]
    if not match:
        raise ValueError(f"no static lease for {mac}")
    return z.delete("static_dhcp", match[0]["Index"])


# ---------------------------------------------------------------- WiFi ----
# The GUI's General WiFi page has no "set channel" call: on Apply it PUTs the
# whole SSID config (incl. security + PSK) to DAL?oid=wlan. wlan_put_payload()
# rebuilds exactly that object from the GET state (mapping copied from the GUI's
# doWifiApply). Validated field-for-field (incl. PSK) against the
# payload the GUI itself produced for 5GHz ch36/80, captured with the request
# blocked. Only channel/bandwidth are substituted; everything else is re-sent
# unchanged from the router's own current state.
WPA_MODE = {
    "WPA-WPA2-Personal": "wpawpa2psk", "WPA2-Enterprise": "wpa2", "WPA-Personal": "wpapsk",
    "WPA2-Personal": "wpa2psk", "WPA3-Personal": "wpa3sae", "DPP": "dpp",
    "DPP+WPA3-Personal": "wpa3saedpp", "DPP+WPA3-Personal-Transition": "wpa2pskwpa3saedpp",
}  # anything else (e.g. WPA3-Personal-Transition) -> "wpa2pskwpa3sae", as in the GUI


def wlan_put_payload(o: dict, channel=None, bandwidth=None) -> dict:
    sm = o["SecurityMode"]
    if sm in ("None", "OWE", "") or "WEP" in sm or o.get("AutoGenPSK"):
        raise ValueError(f"security setup '{sm}' (AutoGenPSK={o.get('AutoGenPSK')}) not covered by this port - use the GUI")
    ch = int(o["channel"] if channel is None else channel)
    bw = str(o["bandwidth"]).replace("MHz", "") if bandwidth is None else str(int(bandwidth))
    iso = bool(o["X_ZYXEL_BssIdIsolation"])
    rate = lambda v: "" if v in (0, "0", None, "") else v  # noqa: E731 - GUI shows 0 as empty
    return {
        "oneSsidEnable": o["oneSsidEnable"], "Index": o["Index"], "wlEnable": o["wlEnable"],
        "X_ZYXEL_Multicast_Fwd": o["X_ZYXEL_Multicast_Fwd"], "oneSsidEnable_ori": o["oneSsidEnable_ori"],
        "SSID": o["SSID"], "upRate": rate(o["upRate"]), "downRate": rate(o["downRate"]),
        "MaxAssociatedDevices": o["MaxAssociatedDevices"], "wlHide": o["wlHide"],
        "secMode": 255, "wpaMode": WPA_MODE.get(sm, "wpa2pskwpa3sae"), "wlpmf": o["wlpmf"],
        "AutoGenPSK": o["AutoGenPSK"], "psk_value": o["PskDisplay"], "encryp": o["encryp"],
        "RekeyingInterval": o["RekeyingInterval"], "X_ZYXEL_Preauth": o["X_ZYXEL_Preauth"],
        "X_ZYXEL_ReauthInterval": o["X_ZYXEL_ReauthInterval"], "RadiusServerIPAddr": o["RadiusServerIPAddr"],
        "RadiusServerPort": o["RadiusServerPort"], "RadiusSecret": o["RadiusSecret"],
        "RadiusAccountingPort": o["RadiusAccountingPort"], "div_wifiAdvance": True,
        "channel": str(ch), "channel_changed": 0 if ch == int(o["channel"]) else 1,
        "bandwidth": bw, "extcha": str(o["extcha"]), "subnetObjAction": "", "div_wifiSubnet": False,
        "IsolationEnable": iso, "X_ZYXEL_BssIdIsolation": iso, "wlEnableGuest": iso, "wlGwMode": "0" if iso else "1",
        "mlo_change": False,
    }


def main_wlan(z, band: str = "5GHz"):
    status, data = z.get("wlan")
    if status != 200 or data.get("result") != "ZCFG_SUCCESS":
        raise RuntimeError(f"reading wlan failed: HTTP {status}")
    return next(o for o in data["Object"] if o["band"] == band and o["MainSSID"])


SECRET_FIELDS = ("PskDisplay", "AutoGenPSKValue", "RadiusSecret", "psk_value")


def cmd_wifi5g(z, args) -> int:
    o = main_wlan(z)
    mode = "auto" if o["AutoChannelEnable"] else "fixed"
    print(f"5GHz '{o['SSID']}': channel {o['channel']} ({mode}), {o['bandwidth']}")
    if len(args) < 2:
        print(f"  80MHz channels : {o['X_ZYXEL_AC80_Channels']}\n  160MHz channels: {o['X_ZYXEL_AX160_Channels']}"
              f"\n  usage: wifi5g <channel> <20|40|80|160> [--apply]")
        return 0
    ch, bw = int(args[0]), int(args[1])
    allowed = {160: o["X_ZYXEL_AX160_Channels"], 80: o["X_ZYXEL_AC80_Channels"],
               40: o["PossibleChannels"], 20: o["PossibleChannels"]}.get(bw)
    if allowed is None:
        raise ValueError("bandwidth must be 20, 40, 80 or 160")
    inactive = {c for c in str(o["X_ZYXEL_InActiveChannels"]).split(",") if c}
    if str(ch) not in str(allowed).split(",") or str(ch) in inactive:
        raise ValueError(f"channel {ch} not valid for {bw}MHz (allowed: {allowed}; inactive: {sorted(inactive) or 'none'})")
    if not o["AutoChannelEnable"] and int(o["channel"]) == ch and str(o["bandwidth"]) == f"{bw}MHz":
        print("  already set - nothing to do")
        return 0
    payload = wlan_put_payload(o, ch, bw)
    print(f"  change: channel {o['channel']} ({mode}), {o['bandwidth']}  ->  channel {ch} (fixed), {bw}MHz")
    print("  effect: the 5GHz radio restarts; 5GHz devices drop and reconnect (about a minute)")
    if "--apply" not in args:
        print("  dry run - add --apply to make the change")
        return 0
    status, res = z._cgi("PUT", "DAL?oid=wlan", payload, timeout=90)
    result = res.get("result") if isinstance(res, dict) else res
    print(f"  PUT wlan: HTTP {status} {result}")
    if status != 200 or result != "ZCFG_SUCCESS":
        return 1
    z._cgi("GET", "Wireless?action=WlCheck", timeout=90)  # the GUI does this after a successful apply
    after = main_wlan(z)
    expected_changes = {"channel", "bandwidth", "AutoChannelEnable", "extcha", "BSSID", "X_ZYXEL_InActiveChannels"}
    unexpected = [k for k in o if k not in expected_changes and o.get(k) != after.get(k)]
    print(f"  read-back: channel {after['channel']} ({'auto' if after['AutoChannelEnable'] else 'fixed'}), {after['bandwidth']}")
    if unexpected:
        print("  WARNING - other fields changed: " + ", ".join(
            k if k in SECRET_FIELDS else f"{k} {o.get(k)!r}->{after.get(k)!r}" for k in unexpected))
        return 1
    print("  all other settings unchanged")
    return 0


def main(argv):
    if len(argv) < 2:
        print(__doc__)
        return 2
    cmd = argv[1]
    # certificate commands: no login involved
    if cmd == "show-cert":
        fp, cert = presented_cert()
        if CERT_SHA256 is None:
            print(f"{describe_cert(fp, cert)}\n  pinned   : none yet\n"
                  f"  -> verify this fingerprint in a browser on another device, then run trust-cert")
            return 3
        status = "MATCHES the pin" if fp == CERT_SHA256 else "DOES NOT MATCH the pin"
        print(f"{describe_cert(fp, cert)}\n  pinned   : {CERT_SHA256}   [{PIN_SOURCE}]\n  -> {status}")
        return 0 if fp == CERT_SHA256 else 3
    if cmd == "trust-cert":
        if len(argv) < 3:
            print("usage: trust-cert <SHA-256 fingerprint you verified independently>")
            return 2
        return trust_cert(argv[2])
    if CERT_SHA256 is None:
        print(f"No certificate pin yet. Run `{os.path.basename(argv[0])} show-cert`, check the fingerprint\n"
              f"against https://{HOST} in a browser on another device, then `trust-cert <fingerprint>`.")
        return 3
    if cmd == "reboot" and "--yes" not in argv:
        print("reboot drops internet/WiFi for a few minutes - rerun with --yes to confirm")
        return 2
    z = Zyxel()
    try:
        z.login()
    except LoginFailed as e:
        print(f"Login failed ({e}). Not retrying - check the password / wait out any lockout.")
        return 1
    except requests.exceptions.SSLError:
        explain_pin_mismatch()
        return 3
    try:
        if cmd == "get":
            status, data = z.get(argv[2])
            print(json.dumps({"http": status, "data": data}, indent=2))
        elif cmd == "port-forwards":
            for r in dal_objects(z, "nat"):
                print(f"#{r['Index']:<3} {'on ' if r['Enable'] else 'off'} {r['Protocol']:<8} "
                      f"{r['ExternalPortStart']}-{r['ExternalPortEnd']} -> {r['InternalClient']}:"
                      f"{r['InternalPortStart']}-{r['InternalPortEnd']}  {r['Description']}")
        elif cmd == "upnp":
            return cmd_upnp(z, argv[2:])
        elif cmd == "static-dhcp":
            for e in static_dhcp_list(z):
                print(f"#{e['Index']:<3} {'on ' if e['Enable'] else 'off'} {e['MACAddr']}  {e['IPAddr']}")
        elif cmd == "add-static-dhcp":
            status, data = add_static_dhcp(z, argv[2], argv[3])
            print(f"HTTP {status}: {data.get('result') if isinstance(data, dict) else data}")
        elif cmd == "delete-static-dhcp":
            status, data = delete_static_dhcp(z, argv[2])
            print(f"HTTP {status}: {data.get('result') if isinstance(data, dict) else data}")
        elif cmd == "wifi5g":
            return cmd_wifi5g(z, argv[2:])
        elif cmd == "reboot":
            status, data = z._cgi("POST", "Reboot")
            print(f"reboot requested: HTTP {status}")
            z.session_key = None  # router is going down; no logout
        else:
            print(f"unknown command {cmd}")
            return 2
    except (ValueError, RuntimeError, IndexError) as e:
        print(f"error: {e}")
        return 1
    finally:
        z.logout()
    return 0


def cli():
    sys.exit(main(sys.argv))


if __name__ == "__main__":
    cli()
