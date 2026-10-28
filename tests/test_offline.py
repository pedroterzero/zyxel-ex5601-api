"""Offline tests: crypto helpers and the Wi-Fi payload builder (no router needed)."""
import base64
import os

import pytest

import zyxel_api as zx


def test_aes_roundtrip():
    key, iv = zx._b64(os.urandom(32)), zx._b64(os.urandom(32))
    text = '{"Input_Account": "admin", "x": "ünïcode"}'
    assert zx.aes_decrypt(zx.aes_encrypt(text, key, iv), key, iv) == text


def test_aes_uses_first_16_iv_bytes():
    key = zx._b64(os.urandom(32))
    iv = os.urandom(32)
    other_tail = iv[:16] + os.urandom(16)
    a = zx.aes_encrypt("same", key, zx._b64(iv))
    b = zx.aes_encrypt("same", key, zx._b64(other_tail))
    assert a == b


def test_norm_fp():
    assert zx._norm_fp("aa bb:CC") == "AA:BB:CC"


def _wlan(**kw):
    o = dict(
        oneSsidEnable=False, Index=5, wlEnable=True, X_ZYXEL_Multicast_Fwd=True, oneSsidEnable_ori=False,
        SSID="test", upRate=0, downRate=0, MaxAssociatedDevices=64, wlHide=False,
        SecurityMode="WPA3-Personal-Transition", wlpmf="capable", AutoGenPSK=False, PskDisplay="secret",
        encryp="aes", RekeyingInterval=3600, X_ZYXEL_Preauth=False, X_ZYXEL_ReauthInterval=0,
        RadiusServerIPAddr="", RadiusServerPort=1812, RadiusSecret="", RadiusAccountingPort=1813,
        channel=36, bandwidth="80MHz", extcha=0, X_ZYXEL_BssIdIsolation=False,
    )
    o.update(kw)
    return o


def test_wlan_payload_changes_only_channel_and_bandwidth():
    p = zx.wlan_put_payload(_wlan(), channel=44, bandwidth=40)
    assert (p["channel"], p["bandwidth"], p["channel_changed"]) == ("44", "40", 1)
    assert p["psk_value"] == "secret" and p["wpaMode"] == "wpa2pskwpa3sae"
    assert p["upRate"] == "" and p["SSID"] == "test"


def test_wlan_payload_refuses_open_networks():
    with pytest.raises(ValueError):
        zx.wlan_put_payload(_wlan(SecurityMode="None"))
