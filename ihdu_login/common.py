import base64
import hashlib
import hmac
import html
import json
import os
import platform
import random
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional

import requests

BASE_URL = "https://login.hdu.edu.cn"
AC_ID = "32"
DEFAULT_INTERVAL = 30
DEFAULT_TIMEOUT = 5.0
DEFAULT_SSID = "i-HDU"
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
