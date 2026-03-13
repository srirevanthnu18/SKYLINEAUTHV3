"""
KeyAuth-Compatible Python SDK
==============================
Pre-configured for: {{APP_NAME}}

Usage:
    import sdk as KeyAuthApp

    KeyAuthApp.init()

    # License-only login
    KeyAuthApp.license("YOUR-LICENSE-KEY")

    # Username + password login
    KeyAuthApp.login("username", "password")

    # Register new account with license key
    KeyAuthApp.register("username", "password", "LICENSE-KEY")

    if KeyAuthApp.response.success:
        print("Authenticated:", KeyAuthApp.user_data.username)
    else:
        print("Error:", KeyAuthApp.response.message)
"""

import requests
import hashlib
import hmac
import uuid
import json


class _UserData:
    username = ""
    ip = ""
    hwid = ""
    createdate = ""
    lastlogin = ""
    subscriptions = []


class _Response:
    success = False
    message = ""


user_data = _UserData()
response = _Response()

name = "{{APP_NAME}}"
ownerid = "{{OWNER_ID}}"
secret = "{{APP_SECRET}}"
version = "{{VERSION}}"
api_url = "{{API_URL}}/"

_sessionid = None
_enckey = None
_initialized = False


def _get_hwid() -> str:
    try:
        return str(uuid.getnode())
    except Exception:
        return "unknown-hwid"


def _req(post_data: dict) -> dict:
    global _enckey, secret
    try:
        res = requests.post(api_url, data=post_data, timeout=10)
        res.raise_for_status()
        raw = res.text
        sig = res.headers.get("signature", "")
        if sig:
            signing_key = f"{_enckey}-{secret}".encode() if _enckey else secret.encode()
            expected = hmac.new(signing_key, raw.encode(), hashlib.sha256).hexdigest()
            if sig != expected:
                return {"success": False, "message": "Signature verification failed"}
        return json.loads(raw)
    except requests.exceptions.Timeout:
        return {"success": False, "message": "Request timed out"}
    except requests.exceptions.ConnectionError:
        return {"success": False, "message": "Cannot connect to auth server"}
    except Exception as e:
        return {"success": False, "message": str(e)}


def _apply(data: dict):
    global response, user_data
    response.success = data.get("success", False)
    response.message = data.get("message", "")
    if response.success and "info" in data:
        info = data["info"]
        user_data.username = info.get("username", "")
        user_data.ip = info.get("ip", "")
        user_data.hwid = info.get("hwid", "")
        user_data.createdate = info.get("createdate", "")
        user_data.lastlogin = info.get("lastlogin", "")
        user_data.subscriptions = info.get("subscriptions", [])


def init() -> bool:
    global _sessionid, _enckey, _initialized
    _enckey = _get_hwid()
    data = _req({"type": "init", "name": name, "ownerid": ownerid, "ver": version, "enckey": _enckey})
    response.success = data.get("success", False)
    response.message = data.get("message", "")
    if response.success:
        _sessionid = data.get("sessionid", "")
        _initialized = True
    else:
        _initialized = False
    return response.success


def login(username: str, password: str, hwid: str = None) -> bool:
    if not _initialized:
        response.success = False; response.message = "Not initialized"; return False
    _apply(_req({"type": "login", "username": username, "pass": password,
                 "hwid": hwid or _get_hwid(), "sessionid": _sessionid,
                 "name": name, "ownerid": ownerid}))
    return response.success


def register(username: str, password: str, license_key: str, hwid: str = None) -> bool:
    if not _initialized:
        response.success = False; response.message = "Not initialized"; return False
    _apply(_req({"type": "register", "username": username, "pass": password,
                 "key": license_key, "hwid": hwid or _get_hwid(),
                 "sessionid": _sessionid, "name": name, "ownerid": ownerid}))
    return response.success


def license(license_key: str, hwid: str = None) -> bool:
    if not _initialized:
        response.success = False; response.message = "Not initialized"; return False
    _apply(_req({"type": "license", "key": license_key, "hwid": hwid or _get_hwid(),
                 "sessionid": _sessionid, "name": name, "ownerid": ownerid}))
    return response.success


def var(varid: str) -> str:
    if not _initialized: return ""
    data = _req({"type": "var", "varid": varid, "sessionid": _sessionid,
                 "name": name, "ownerid": ownerid})
    response.success = data.get("success", False)
    response.message = data.get("message", "")
    return data.get("message", "") if response.success else ""


def log(message: str, pcname: str = "Python"):
    if not _initialized: return
    _req({"type": "log", "message": message, "pcname": pcname,
          "sessionid": _sessionid, "name": name, "ownerid": ownerid})


def check() -> bool:
    if not _initialized: return False
    data = _req({"type": "check", "sessionid": _sessionid, "name": name, "ownerid": ownerid})
    response.success = data.get("success", False)
    response.message = data.get("message", "")
    return response.success


def checkblacklist() -> bool:
    if not _initialized: return False
    data = _req({"type": "checkblacklist", "hwid": _get_hwid(),
                 "sessionid": _sessionid, "name": name, "ownerid": ownerid})
    return data.get("success", False)
