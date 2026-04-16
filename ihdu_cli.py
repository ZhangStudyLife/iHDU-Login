import argparse
import base64
import getpass
import hashlib
import hmac
import html
import json
import os
import platform
import queue
import random
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests

try:
    import keyring
except Exception:
    keyring = None

try:
    import tkinter as tk
    from tkinter import messagebox, ttk
except Exception:
    tk = None
    messagebox = None
    ttk = None

try:
    import pystray
    from PIL import Image, ImageDraw
except Exception:
    pystray = None
    Image = None
    ImageDraw = None

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except Exception:
    Fernet = None
    InvalidToken = Exception
    PBKDF2HMAC = None
    hashes = None

BASE_URL = "https://login.hdu.edu.cn"
AC_ID = "32"
DEFAULT_INTERVAL = 30
DEFAULT_TIMEOUT = 5.0
DEFAULT_SSID = "i-HDU"
CONFIG_DIR = Path.home() / ".ihdu_login"
CONFIG_FILE = CONFIG_DIR / "config.json"
FALLBACK_SECRET_FILE = CONFIG_DIR / "secret.bin"
KEYRING_SERVICE = "iHDU-Login"
TRAY_ICON_SIZE = 64
TRAY_ICON_PADDING = 8
PBKDF2_ITERATIONS = 600000
MIN_RETRY_INTERVAL = 5
MAX_RETRY_INTERVAL = 15
WINDOWS_OPEN_WIFI_PROFILE = """<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>open</authentication>
                <encryption>none</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
        </security>
    </MSM>
</WLANProfile>
"""

SRBX1_ALPHA = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
STD_BASE64_ALPHA = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"


def parse_jsonp(payload: str) -> Dict[str, Any]:
    payload = payload.strip()
    match = re.search(r"^[^(]+\((.*)\)\s*$", payload, re.S)
    if not match:
        raise ValueError("响应内容不是合法的 JSONP")
    return json.loads(match.group(1))


def _srun_xencode(message: str, key: str) -> str:
    if message == "":
        return ""

    def s(value: str, include_length: bool) -> List[int]:
        buf: List[int] = []
        for index in range(0, len(value), 4):
            buf.append(
                (
                    (ord(value[index]) if index < len(value) else 0)
                    | ((ord(value[index + 1]) if index + 1 < len(value) else 0) << 8)
                    | ((ord(value[index + 2]) if index + 2 < len(value) else 0) << 16)
                    | ((ord(value[index + 3]) if index + 3 < len(value) else 0) << 24)
                )
                & 0xFFFFFFFF
            )
        if include_length:
            buf.append(len(value))
        return buf

    def l(value: List[int], include_length: bool) -> str:
        length = (len(value) - 1) << 2
        if include_length:
            size = value[-1]
            if size < length - 3 or size > length:
                raise ValueError("SRBX1 长度非法")
            length = size

        chars: List[str] = []
        for item in value:
            item &= 0xFFFFFFFF
            chars.append(chr(item & 0xFF))
            chars.append(chr((item >> 8) & 0xFF))
            chars.append(chr((item >> 16) & 0xFF))
            chars.append(chr((item >> 24) & 0xFF))
        text = "".join(chars)
        return text[:length] if include_length else text

    values = s(message, True)
    key_values = s(key, False)
    while len(key_values) < 4:
        key_values.append(0)

    n = len(values) - 1
    z = values[n]
    c = (0x86014019 | 0x183639A0) & 0xFFFFFFFF
    q = int(6 + 52 / (n + 1))
    d = 0

    while q > 0:
        q -= 1
        d = (d + c) & (0x8CE0D9BF | 0x731F2640)
        e = (d >> 2) & 3
        for p in range(n):
            y = values[p + 1]
            m = ((z >> 5) ^ ((y << 2) & 0xFFFFFFFF)) & 0xFFFFFFFF
            m = (m + (((y >> 3) ^ ((z << 4) & 0xFFFFFFFF) ^ (d ^ y)) & 0xFFFFFFFF)) & 0xFFFFFFFF
            m = (m + ((key_values[(p & 3) ^ e] ^ z) & 0xFFFFFFFF)) & 0xFFFFFFFF
            z = values[p] = (values[p] + m) & (0xEFB8D130 | 0x10472ECF)

        y = values[0]
        m = ((z >> 5) ^ ((y << 2) & 0xFFFFFFFF)) & 0xFFFFFFFF
        m = (m + (((y >> 3) ^ ((z << 4) & 0xFFFFFFFF) ^ (d ^ y)) & 0xFFFFFFFF)) & 0xFFFFFFFF
        m = (m + ((key_values[(n & 3) ^ e] ^ z) & 0xFFFFFFFF)) & 0xFFFFFFFF
        z = values[n] = (values[n] + m) & (0xBB390742 | 0x44C6F8BD)

    return l(values, False)


def _custom_base64(raw: str) -> str:
    encoded = base64.b64encode(raw.encode("latin1")).decode("ascii")
    return encoded.translate(str.maketrans(STD_BASE64_ALPHA, SRBX1_ALPHA))


def encode_info(info: Dict[str, str], token: str) -> str:
    info_text = json.dumps(info, ensure_ascii=False, separators=(",", ":"))
    return "{SRBX1}" + _custom_base64(_srun_xencode(info_text, token))


def _hmac_md5(password: str, token: str) -> str:
    return hmac.new(token.encode("utf-8"), password.encode("utf-8"), hashlib.md5).hexdigest()


def build_login_params(
    username: str,
    password: str,
    ip: str,
    ac_id: str,
    token: str,
    os_name: str = "Linux",
    platform_name: str = "Linux",
    domain: str = "",
) -> Dict[str, str]:
    full_username = username + domain
    n = "200"
    login_type = "1"
    enc_ver = "srun_bx1"
    password_md5 = _hmac_md5(password, token)
    info = encode_info(
        {
            "username": full_username,
            "password": password,
            "ip": ip,
            "acid": str(ac_id),
            "enc_ver": enc_ver,
        },
        token,
    )
    checksum_text = (
        token
        + full_username
        + token
        + password_md5
        + token
        + str(ac_id)
        + token
        + ip
        + token
        + n
        + token
        + login_type
        + token
        + info
    )
    return {
        "action": "login",
        "username": full_username,
        "password": "{MD5}" + password_md5,
        "os": os_name,
        "name": platform_name,
        "double_stack": "0",
        "chksum": hashlib.sha1(checksum_text.encode("utf-8")).hexdigest(),
        "info": info,
        "ac_id": str(ac_id),
        "ip": ip,
        "n": n,
        "type": login_type,
    }


def detect_user_agent() -> str:
    system_name = platform.system()
    if system_name == "Darwin":
        return (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/146.0.0.0 Safari/537.36"
        )
    if system_name == "Windows":
        return (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/146.0.0.0 Safari/537.36"
        )
    return (
        "Mozilla/5.0 (X11; Linux x86_64) "
        "AppleWebKit/537.36 (KHTML, like Gecko) "
        "Chrome/146.0.0.0 Safari/537.36"
    )


def infer_ipv4_address() -> Optional[str]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("223.5.5.5", 80))
        return sock.getsockname()[0]
    except OSError:
        return None
    finally:
        sock.close()


def run_command(command: List[str], timeout: float = 15) -> subprocess.CompletedProcess:
    kwargs: Dict[str, Any] = {
        "args": command,
        "capture_output": True,
        "text": True,
        "timeout": timeout,
        "check": False,
    }
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.run(**kwargs)


def get_macos_wifi_device() -> Optional[str]:
    result = run_command(["networksetup", "-listallhardwareports"])
    if result.returncode != 0:
        return None
    hardware_port = ""
    for line in result.stdout.splitlines():
        if line.startswith("Hardware Port:"):
            hardware_port = line.split(":", 1)[1].strip()
            continue
        if hardware_port in {"Wi-Fi", "AirPort"} and line.startswith("Device:"):
            return line.split(":", 1)[1].strip()
    return None


def get_connected_ssid() -> Optional[str]:
    system_name = platform.system()

    if system_name == "Windows":
        result = run_command(["netsh", "wlan", "show", "interfaces"])
        if result.returncode != 0:
            return None
        for line in result.stdout.splitlines():
            if "BSSID" in line:
                continue
            match = re.search(r"^\s*SSID\s*:\s*(.+?)\s*$", line)
            if match and match.group(1) and match.group(1) != "":
                return match.group(1)
        return None

    if system_name == "Darwin":
        device = get_macos_wifi_device()
        if not device:
            return None
        result = run_command(["networksetup", "-getairportnetwork", device])
        if result.returncode != 0:
            return None
        match = re.search(r"Current Wi-Fi Network:\s*(.+?)\s*$", result.stdout)
        return match.group(1) if match else None

    if shutil.which("nmcli") is None:
        return None
    result = run_command(["nmcli", "-t", "-f", "ACTIVE,SSID", "dev", "wifi"])
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        if line.startswith("yes:"):
            return line.split(":", 1)[1]
    return None


def _ensure_windows_open_profile(ssid: str) -> None:
    profiles = run_command(["netsh", "wlan", "show", "profiles"])
    if profiles.returncode == 0 and ssid in profiles.stdout:
        return

    xml_text = WINDOWS_OPEN_WIFI_PROFILE.format(ssid=html.escape(ssid))
    profile_path = ""
    try:
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".xml", encoding="utf-8") as handle:
            handle.write(xml_text)
            profile_path = handle.name
        result = run_command(["netsh", "wlan", "add", "profile", f"filename={profile_path}", "user=current"])
        if result.returncode != 0:
            raise RuntimeError(f"添加 Windows Wi-Fi 配置失败：{result.stderr.strip() or result.stdout.strip()}")
    finally:
        if profile_path and os.path.exists(profile_path):
            os.remove(profile_path)


def ensure_wifi_connected(ssid: str) -> bool:
    if get_connected_ssid() == ssid:
        return False

    system_name = platform.system()

    if system_name == "Windows":
        _ensure_windows_open_profile(ssid)
        result = run_command(["netsh", "wlan", "connect", f"name={ssid}", f"ssid={ssid}"])
        if result.returncode != 0:
            raise RuntimeError(f"连接 Wi-Fi 失败：{result.stderr.strip() or result.stdout.strip()}")
        return True

    if system_name == "Darwin":
        device = get_macos_wifi_device()
        if not device:
            raise RuntimeError("未找到 macOS 的 Wi-Fi 网卡设备。")
        result = run_command(["networksetup", "-setairportnetwork", device, ssid])
        if result.returncode != 0:
            raise RuntimeError(f"连接 Wi-Fi 失败：{result.stderr.strip() or result.stdout.strip()}")
        return True

    if shutil.which("nmcli") is None:
        raise RuntimeError(f"系统中未找到命令 `nmcli`，无法自动连接 Wi-Fi。")
    result = run_command(["nmcli", "device", "wifi", "connect", ssid])
    if result.returncode != 0:
        raise RuntimeError(f"连接 Wi-Fi 失败：{result.stderr.strip() or result.stdout.strip()}")
    return True


def summarize_status(payload: Dict[str, Any]) -> str:
    if payload.get("error") != "ok":
        return f"当前不在线，返回信息：{payload.get('error_msg') or payload.get('error') or '未知'}"

    username = payload.get("user_name") or payload.get("username") or "未知账号"
    online_ip = payload.get("online_ip") or "未知 IP"
    products_name = payload.get("products_name") or payload.get("billing_name") or "未知套餐"
    return f"当前在线，账号：{username}，IP：{online_ip}，套餐：{products_name}"


def summarize_login(payload: Dict[str, Any]) -> str:
    username = payload.get("username") or payload.get("user_name") or "未知账号"
    online_ip = payload.get("online_ip") or payload.get("client_ip") or "未知 IP"
    message = payload.get("suc_msg") or payload.get("ploy_msg") or payload.get("error_msg") or "ok"
    return f"登录成功，账号：{username}，IP：{online_ip}，网关返回：{message}"


class IHDUClient:
    def __init__(self, username: str, password: str) -> None:
        self.username = username
        self.password = password
        self.base_url = BASE_URL
        self.ac_id = AC_ID
        self.ip: Optional[str] = None
        self.timeout = DEFAULT_TIMEOUT

        system_name = platform.system()
        if system_name == "Darwin":
            self.os_name = "Mac OS"
            self.platform_name = "Macintosh"
        elif system_name == "Windows":
            self.os_name = f"Windows {platform.release()}"
            self.platform_name = "Windows"
        else:
            self.os_name = "Linux"
            self.platform_name = "Linux"

        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": detect_user_agent(),
                "Referer": f"{self.base_url}/srun_portal_pc?ac_id={self.ac_id}&theme=pro",
                "Accept": "text/javascript, application/javascript, */*; q=0.01",
            }
        )

    def _callback(self) -> str:
        return f"jQuery{int(time.time() * 1000)}_{random.randint(100000, 999999)}"

    def _jsonp_get(self, path: str, params: Optional[Dict[str, str]] = None) -> Dict[str, Any]:
        query = dict(params or {})
        query["callback"] = self._callback()
        query["_"] = str(int(time.time() * 1000))
        response = self.session.get(f"{self.base_url}{path}", params=query, timeout=self.timeout)
        response.raise_for_status()
        return parse_jsonp(response.text)

    def resolve_ip(self) -> str:
        if self.ip:
            return self.ip
        ip = infer_ipv4_address()
        if ip:
            self.ip = ip
            return self.ip

        changed = ensure_wifi_connected(DEFAULT_SSID)
        if changed:
            time.sleep(2)

        ip = infer_ipv4_address()
        if not ip:
            raise RuntimeError(f"已尝试连接 Wi-Fi `{DEFAULT_SSID}`，但仍未获取到本机 IP。")
        self.ip = ip
        return self.ip

    def status(self) -> Dict[str, Any]:
        params: Dict[str, str] = {}
        if self.ip:
            params["ip"] = self.ip
        return self._jsonp_get("/cgi-bin/rad_user_info", params)

    def is_online(self) -> bool:
        try:
            payload = self.status()
        except Exception:
            return False
        if payload.get("error") != "ok":
            return False
        if payload.get("online_ip"):
            self.ip = payload["online_ip"]
        return True

    def get_challenge(self) -> str:
        payload = self._jsonp_get(
            "/cgi-bin/get_challenge",
            {
                "username": self.username,
                "ip": self.resolve_ip(),
            },
        )
        challenge = payload.get("challenge")
        if not challenge:
            raise RuntimeError(f"获取 challenge 失败：{payload}")
        return challenge

    def login(self) -> Dict[str, Any]:
        ip = self.resolve_ip()
        token = self.get_challenge()
        params = build_login_params(
            username=self.username,
            password=self.password,
            ip=ip,
            ac_id=self.ac_id,
            token=token,
            os_name=self.os_name,
            platform_name=self.platform_name,
        )
        payload = self._jsonp_get("/cgi-bin/srun_portal", params)
        if payload.get("error") != "ok":
            raise RuntimeError(json.dumps(payload, ensure_ascii=False))
        return payload

    def watch(self, interval: int) -> None:
        while True:
            try:
                if self.is_online():
                    print(f"[{time.strftime('%H:%M:%S')}] {summarize_status({'error': 'ok', 'user_name': self.username, 'online_ip': self.ip})}")
                else:
                    print(f"[{time.strftime('%H:%M:%S')}] 当前离线，开始尝试重连……")
                    result = self.login()
                    print(f"[{time.strftime('%H:%M:%S')}] {summarize_login(result)}")
            except Exception as exc:
                print(f"[{time.strftime('%H:%M:%S')}] 发生错误：{exc}", file=sys.stderr)
            time.sleep(interval)


class CredentialStore:
    def __init__(self) -> None:
        self.config_dir = CONFIG_DIR
        self.config_file = CONFIG_FILE
        self.fallback_secret_file = FALLBACK_SECRET_FILE
        self.device_key_file = self.config_dir / "device.key"

    def _ensure_dir(self) -> None:
        self.config_dir.mkdir(parents=True, exist_ok=True)

    def load_config(self) -> Dict[str, Any]:
        defaults: Dict[str, Any] = {
            "username": "",
            "interval": DEFAULT_INTERVAL,
            "autostart": False,
            "minimize_to_tray": True,
        }
        if not self.config_file.exists():
            return defaults
        try:
            with self.config_file.open("r", encoding="utf-8") as handle:
                data = json.load(handle)
            if not isinstance(data, dict):
                return defaults
            merged = dict(defaults)
            merged.update(data)
            return merged
        except Exception:
            return defaults

    def save_config(self, config: Dict[str, Any]) -> None:
        self._ensure_dir()
        with self.config_file.open("w", encoding="utf-8") as handle:
            json.dump(config, handle, ensure_ascii=False, indent=2)

    def _device_secret(self) -> bytes:
        self._ensure_dir()
        if self.device_key_file.exists():
            raw = self.device_key_file.read_bytes()
            if raw:
                return raw
        raw = os.urandom(32)
        self.device_key_file.write_bytes(raw)
        try:
            os.chmod(self.device_key_file, 0o600)
        except Exception:
            pass
        return raw

    def _derive_key(self, username: str, salt: bytes) -> bytes:
        if PBKDF2HMAC is None or hashes is None:
            raise RuntimeError("缺少 cryptography 依赖库，请运行 pip install cryptography 后重试。")
        seed = f"{platform.system()}|{platform.node()}|{uuid.getnode()}|{username}".encode("utf-8") + self._device_secret()
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=PBKDF2_ITERATIONS)
        return base64.urlsafe_b64encode(kdf.derive(seed))

    def _save_fallback_password(self, username: str, password: str) -> None:
        if Fernet is None:
            raise RuntimeError("缺少 cryptography 依赖库，请运行 pip install cryptography 后重试。")
        self._ensure_dir()
        salt = os.urandom(16)
        key = self._derive_key(username, salt)
        cipher = Fernet(key).encrypt(password.encode("utf-8"))
        payload = {
            "username": username,
            "salt": base64.b64encode(salt).decode("ascii"),
            "cipher": base64.b64encode(cipher).decode("ascii"),
        }
        with self.fallback_secret_file.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, ensure_ascii=False)

    def _load_fallback_password(self, username: str) -> str:
        if not self.fallback_secret_file.exists():
            return ""
        try:
            with self.fallback_secret_file.open("r", encoding="utf-8") as handle:
                payload = json.load(handle)
            if payload.get("username") != username:
                return ""
            if Fernet is None:
                return ""
            salt = base64.b64decode(payload["salt"])
            cipher = base64.b64decode(payload["cipher"])
            key = self._derive_key(username, salt)
            plain = Fernet(key).decrypt(cipher)
            return plain.decode("utf-8")
        except InvalidToken:
            return ""
        except Exception:
            return ""

    def set_password(self, username: str, password: str) -> None:
        if not username:
            return
        if keyring is not None:
            try:
                keyring.set_password(KEYRING_SERVICE, username, password)
                return
            except Exception:
                pass
        self._save_fallback_password(username, password)

    def get_password(self, username: str) -> str:
        if not username:
            return ""
        if keyring is not None:
            try:
                password = keyring.get_password(KEYRING_SERVICE, username)
                if password:
                    return password
            except Exception:
                pass
        return self._load_fallback_password(username)


class AutoStartManager:
    def __init__(self) -> None:
        self.script_path = str(Path(__file__).resolve())
        self.python_path = sys.executable

    def _windows_path(self) -> Path:
        appdata = os.environ.get("APPDATA", "")
        return Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup" / "ihdu-login.bat"

    def _linux_path(self) -> Path:
        return Path.home() / ".config" / "autostart" / "ihdu-login.desktop"

    def _macos_path(self) -> Path:
        return Path.home() / "Library" / "LaunchAgents" / "com.ihdu.login.plist"

    def is_enabled(self) -> bool:
        system_name = platform.system()
        if system_name == "Windows":
            return self._windows_path().exists()
        if system_name == "Darwin":
            return self._macos_path().exists()
        return self._linux_path().exists()

    def set_enabled(self, enabled: bool) -> None:
        system_name = platform.system()
        if system_name == "Windows":
            path = self._windows_path()
            if enabled:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(
                    f'@echo off\nstart "" "{self.python_path}" "{self.script_path}" ui --headless\n',
                    encoding="utf-8",
                )
            elif path.exists():
                path.unlink()
            return

        if system_name == "Darwin":
            path = self._macos_path()
            if enabled:
                path.parent.mkdir(parents=True, exist_ok=True)
                plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.ihdu.login</string>
  <key>ProgramArguments</key>
  <array>
    <string>{self.python_path}</string>
    <string>{self.script_path}</string>
    <string>ui</string>
    <string>--headless</string>
  </array>
  <key>RunAtLoad</key><true/>
</dict>
</plist>
"""
                path.write_text(plist, encoding="utf-8")
            elif path.exists():
                path.unlink()
            return

        path = self._linux_path()
        if enabled:
            path.parent.mkdir(parents=True, exist_ok=True)
            desktop = f"""[Desktop Entry]
Type=Application
Name=iHDU Login
Exec="{self.python_path}" "{self.script_path}" ui --headless
X-GNOME-Autostart-enabled=true
"""
            path.write_text(desktop, encoding="utf-8")
        elif path.exists():
            path.unlink()


class AuthWorker:
    def __init__(self, username: str, password: str, interval: int) -> None:
        self.username = username
        self.password = password
        self.interval = max(MIN_RETRY_INTERVAL, int(interval))
        self._events: "queue.Queue[Dict[str, Any]]" = queue.Queue()
        self._stop_event = threading.Event()
        self._reconnect_event = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self) -> None:
        if not self._thread.is_alive():
            self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        self._reconnect_event.set()
        if self._thread.is_alive():
            self._thread.join(timeout=2)

    def reconnect_now(self) -> None:
        self._reconnect_event.set()

    def fetch_events(self) -> List[Dict[str, Any]]:
        result: List[Dict[str, Any]] = []
        while True:
            try:
                result.append(self._events.get_nowait())
            except queue.Empty:
                break
        return result

    def _emit(self, level: str, message: str) -> None:
        self._events.put({"time": time.strftime("%H:%M:%S"), "level": level, "message": message})

    def _wait_with_interrupt(self, seconds: int) -> None:
        deadline = time.time() + max(0, seconds)
        while time.time() < deadline:
            if self._stop_event.is_set() or self._reconnect_event.is_set():
                return
            time.sleep(0.25)

    def _run(self) -> None:
        client = IHDUClient(username=self.username, password=self.password)
        self._emit("info", "后台认证服务已启动。")
        while not self._stop_event.is_set():
            try:
                if client.is_online():
                    self._emit(
                        "online",
                        summarize_status({"error": "ok", "user_name": self.username, "online_ip": client.ip}),
                    )
                    wait_seconds = self.interval
                else:
                    self._emit("warn", "当前离线，开始自动认证。")
                    payload = client.login()
                    self._emit("ok", summarize_login(payload))
                    wait_seconds = self.interval
            except Exception as exc:
                message = str(exc)
                if "timed out" in message.lower():
                    prefix = "网络超时"
                elif "连接 Wi-Fi 失败" in message or "未获取到本机 IP" in message:
                    prefix = "Wi-Fi 异常"
                elif "error" in message.lower():
                    prefix = "认证失败"
                else:
                    prefix = "未知错误"
                self._emit("error", f"{prefix}：{message}")
                wait_seconds = min(MAX_RETRY_INTERVAL, max(MIN_RETRY_INTERVAL, self.interval // 2))

            self._wait_with_interrupt(wait_seconds)
            if self._reconnect_event.is_set():
                self._reconnect_event.clear()
                self._emit("info", "收到手动重连请求，立即执行认证。")

        self._emit("info", "后台认证服务已停止。")


class IHDUUiApp:
    def __init__(self, headless: bool = False) -> None:
        if tk is None or ttk is None or messagebox is None:
            raise RuntimeError("当前环境不支持 tkinter。请先安装 Python Tk 支持（例如 Ubuntu: sudo apt-get install python3-tk）。")
        self.root = tk.Tk()
        self.root.title("iHDU Login")
        self.root.geometry("620x420")
        self.root.minsize(560, 380)

        self.store = CredentialStore()
        self.autostart = AutoStartManager()
        self.worker: Optional[AuthWorker] = None
        self.tray_icon = None
        self.headless = headless

        config = self.store.load_config()
        self.username_var = tk.StringVar(value=str(config.get("username", "")))
        self.password_var = tk.StringVar(value="")
        self.interval_var = tk.StringVar(value=str(config.get("interval", DEFAULT_INTERVAL)))
        self.autostart_var = tk.BooleanVar(value=bool(config.get("autostart", self.autostart.is_enabled())))
        self.minimize_to_tray_var = tk.BooleanVar(value=bool(config.get("minimize_to_tray", True)))
        self.status_var = tk.StringVar(value="准备就绪。")

        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        if self.username_var.get():
            cached = self.store.get_password(self.username_var.get().strip())
            if cached:
                self.password_var.set(cached)

        if self.headless:
            self.root.withdraw()
            self._start_worker(auto=True)
        self._poll_events()

    def _build_ui(self) -> None:
        style = ttk.Style(self.root)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure("TLabel", padding=2)
        style.configure("TButton", padding=6)

        frame = ttk.Frame(self.root, padding=16)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="账号").grid(row=0, column=0, sticky=tk.W, pady=4)
        ttk.Entry(frame, textvariable=self.username_var).grid(row=0, column=1, sticky=tk.EW, pady=4)

        ttk.Label(frame, text="密码").grid(row=1, column=0, sticky=tk.W, pady=4)
        ttk.Entry(frame, textvariable=self.password_var, show="*").grid(row=1, column=1, sticky=tk.EW, pady=4)

        ttk.Label(frame, text="轮询间隔（秒）").grid(row=2, column=0, sticky=tk.W, pady=4)
        ttk.Entry(frame, textvariable=self.interval_var).grid(row=2, column=1, sticky=tk.EW, pady=4)

        ttk.Checkbutton(frame, text="开机自启", variable=self.autostart_var).grid(row=3, column=0, sticky=tk.W, pady=6)
        ttk.Checkbutton(frame, text="关闭窗口时最小化到托盘", variable=self.minimize_to_tray_var).grid(
            row=3, column=1, sticky=tk.W, pady=6
        )

        button_frame = ttk.Frame(frame)
        button_frame.grid(row=4, column=0, columnspan=2, sticky=tk.EW, pady=8)
        ttk.Button(button_frame, text="保存配置", command=self._save_config).pack(side=tk.LEFT, padx=4)
        ttk.Button(button_frame, text="启动后台", command=lambda: self._start_worker(auto=False)).pack(side=tk.LEFT, padx=4)
        ttk.Button(button_frame, text="停止后台", command=self._stop_worker).pack(side=tk.LEFT, padx=4)
        ttk.Button(button_frame, text="立即重连", command=self._reconnect_now).pack(side=tk.LEFT, padx=4)

        ttk.Label(frame, textvariable=self.status_var).grid(row=5, column=0, columnspan=2, sticky=tk.W, pady=6)
        self.log_text = tk.Text(frame, height=12, wrap=tk.WORD)
        self.log_text.grid(row=6, column=0, columnspan=2, sticky=tk.NSEW)
        self.log_text.configure(state=tk.DISABLED)

        frame.columnconfigure(1, weight=1)
        frame.rowconfigure(6, weight=1)

    def _append_log(self, text: str) -> None:
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, text + "\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def _save_config(self) -> bool:
        username = self.username_var.get().strip()
        password = self.password_var.get()
        try:
            interval = max(MIN_RETRY_INTERVAL, int(self.interval_var.get().strip()))
            self.interval_var.set(str(interval))
        except Exception:
            messagebox.showerror("配置错误", f"轮询间隔必须是整数，且不小于 {MIN_RETRY_INTERVAL} 秒。")
            return False
        if not username:
            messagebox.showerror("配置错误", "账号不能为空。")
            return False
        if not password:
            password = self.store.get_password(username)
            if not password:
                messagebox.showerror("配置错误", "密码不能为空。")
                return False
        self.store.save_config(
            {
                "username": username,
                "interval": interval,
                "autostart": bool(self.autostart_var.get()),
                "minimize_to_tray": bool(self.minimize_to_tray_var.get()),
            }
        )
        self.store.set_password(username, password)
        self.password_var.set("")
        try:
            self.autostart.set_enabled(bool(self.autostart_var.get()))
        except Exception as exc:
            self._append_log(f"[{time.strftime('%H:%M:%S')}] [error] 设置开机自启失败：{exc}")
        self.status_var.set("配置已保存。")
        self._append_log(f"[{time.strftime('%H:%M:%S')}] [info] 配置已保存。")
        return True

    def _start_worker(self, auto: bool) -> None:
        if self.worker is not None:
            self.status_var.set("后台服务已在运行。")
            return
        if not self._save_config():
            return
        username = self.username_var.get().strip()
        password = self.password_var.get().strip() or self.store.get_password(username)
        interval = int(self.interval_var.get().strip())
        self.worker = AuthWorker(username=username, password=password, interval=interval)
        self.worker.start()
        reason = "静默启动" if auto else "手动启动"
        self.status_var.set(f"后台服务运行中（{reason}）。")
        self._append_log(f"[{time.strftime('%H:%M:%S')}] [info] 后台服务已启动（{reason}）。")

    def _stop_worker(self) -> None:
        if self.worker is None:
            self.status_var.set("后台服务未运行。")
            return
        self.worker.stop()
        self.worker = None
        self.status_var.set("后台服务已停止。")
        self._append_log(f"[{time.strftime('%H:%M:%S')}] [info] 后台服务已停止。")

    def _reconnect_now(self) -> None:
        if self.worker is None:
            self._start_worker(auto=False)
            return
        self.worker.reconnect_now()
        self.status_var.set("已发送立即重连请求。")

    def _ensure_tray_icon(self) -> bool:
        if pystray is None or Image is None or ImageDraw is None:
            return False
        if self.tray_icon is not None:
            return True
        icon_image = Image.new("RGB", (TRAY_ICON_SIZE, TRAY_ICON_SIZE), "#1e293b")
        draw = ImageDraw.Draw(icon_image)
        draw.rounded_rectangle(
            (
                TRAY_ICON_PADDING,
                TRAY_ICON_PADDING,
                TRAY_ICON_SIZE - TRAY_ICON_PADDING,
                TRAY_ICON_SIZE - TRAY_ICON_PADDING,
            ),
            radius=12,
            fill="#2563eb",
        )
        text = "H"
        text_box = draw.textbbox((0, 0), text)
        text_width = text_box[2] - text_box[0]
        text_height = text_box[3] - text_box[1]
        text_x = (TRAY_ICON_SIZE - text_width) // 2
        text_y = (TRAY_ICON_SIZE - text_height) // 2
        draw.text((text_x, text_y), text, fill="white")

        def show_window(icon: Any = None, item: Any = None) -> None:
            self.root.after(0, self._restore_from_tray)

        def exit_app(icon: Any = None, item: Any = None) -> None:
            self.root.after(0, self._quit_app)

        menu = pystray.Menu(pystray.MenuItem("显示窗口", show_window), pystray.MenuItem("退出", exit_app))
        self.tray_icon = pystray.Icon("ihdu-login", icon_image, "iHDU Login", menu)
        self.tray_icon.run_detached()
        return True

    def _restore_from_tray(self) -> None:
        self.root.deiconify()
        self.root.lift()
        self.root.focus_force()

    def _on_close(self) -> None:
        if self.minimize_to_tray_var.get() and self._ensure_tray_icon():
            self.root.withdraw()
            self.status_var.set("已最小化到托盘，后台继续运行。")
            return
        self._quit_app()

    def _quit_app(self) -> None:
        self._stop_worker()
        if self.tray_icon is not None:
            try:
                self.tray_icon.stop()
            except Exception:
                pass
            self.tray_icon = None
        self.root.destroy()

    def _poll_events(self) -> None:
        if self.worker is not None:
            for event in self.worker.fetch_events():
                log_line = f"[{event['time']}] [{event['level']}] {event['message']}"
                self.status_var.set(event["message"])
                self._append_log(log_line)
        self.root.after(700, self._poll_events)

    def run(self) -> None:
        self.root.mainloop()


def run_ui(headless: bool = False) -> int:
    app = IHDUUiApp(headless=headless)
    app.run()
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="i-HDU 校园网命令行登录工具")
    parser.add_argument("--username", help="校园网账号")
    parser.add_argument("--password", help="校园网密码")

    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("status", help="查询当前在线状态")
    subparsers.add_parser("login", help="执行一次登录")
    watch_parser = subparsers.add_parser("watch", help="持续检测，掉线自动重登")
    watch_parser.add_argument("--interval", type=int, default=DEFAULT_INTERVAL, help=f"检测间隔秒数，默认 {DEFAULT_INTERVAL}")
    ui_parser = subparsers.add_parser("ui", help="启动可视化后台认证界面")
    ui_parser.add_argument("--headless", action="store_true", help="静默启动，仅在后台运行")

    args = parser.parse_args()

    username = ""
    password = ""
    if args.command in {"login", "watch"}:
        username = args.username or input("请输入校园网账号: ").strip()
        password = args.password if args.password is not None else getpass.getpass("请输入校园网密码: ")
        if not username or not password:
            raise SystemExit("账号或密码为空，无法继续登录。")

    client = IHDUClient(username=username, password=password)

    try:
        if args.command == "status":
            print(summarize_status(client.status()))
            return 0

        if args.command == "login":
            payload = client.login()
            print(summarize_login(payload))
            return 0

        if args.command == "watch":
            client.watch(args.interval)
            return 0

        if args.command == "ui":
            return run_ui(headless=bool(args.headless))

        parser.error("未知命令")
        return 2
    except KeyboardInterrupt:
        print("用户中断。", file=sys.stderr)
        return 130
    except Exception as exc:
        print(f"操作失败：{exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
