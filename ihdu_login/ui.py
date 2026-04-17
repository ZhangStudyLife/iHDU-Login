import base64
import json
import os
import platform
import queue
import sys
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

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
    from PIL import Image, ImageDraw, ImageFont
except Exception:
    pystray = None
    Image = None
    ImageDraw = None
    ImageFont = None

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except Exception:
    Fernet = None
    InvalidToken = Exception
    PBKDF2HMAC = None
    hashes = None

from .common import DEFAULT_INTERVAL, IHDUClient, summarize_login, summarize_status

CONFIG_DIR = Path.home() / ".ihdu_login"
CONFIG_FILE = CONFIG_DIR / "config.json"
FALLBACK_SECRET_FILE = CONFIG_DIR / "secret.bin"
KEYRING_SERVICE = "iHDU-Login"
TRAY_ICON_SIZE = 64
TRAY_ICON_PADDING = 8
PBKDF2_ITERATIONS = 600000
MIN_RETRY_INTERVAL = 5
MAX_RETRY_INTERVAL = 15


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
    def __init__(self, script_path: Optional[str] = None) -> None:
        self.script_path = str(Path(script_path or sys.argv[0]).resolve())
        self.python_path = sys.executable
        self.frozen = bool(getattr(sys, "frozen", False))

    def _windows_path(self) -> Path:
        appdata = os.environ.get("APPDATA", "")
        return Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup" / "ihdu-login.bat"

    def _escape_windows_batch_arg(self, value: str) -> str:
        escaped = (
            value.replace("^", "^^")
            .replace("%", "%%")
            .replace("&", "^&")
            .replace("|", "^|")
            .replace("<", "^<")
            .replace(">", "^>")
        )
        return f'"{escaped}"'

    def _linux_path(self) -> Path:
        return Path.home() / ".config" / "autostart" / "ihdu-login.desktop"

    def _macos_path(self) -> Path:
        return Path.home() / "Library" / "LaunchAgents" / "com.ihdu.login.plist"

    def _launch_args(self) -> List[str]:
        if self.frozen:
            return [self.script_path, "ui", "--headless"]
        return [self.python_path, self.script_path, "ui", "--headless"]

    def is_enabled(self) -> bool:
        system_name = platform.system()
        if system_name == "Windows":
            return self._windows_path().exists()
        if system_name == "Darwin":
            return self._macos_path().exists()
        return self._linux_path().exists()

    def set_enabled(self, enabled: bool) -> None:
        launch_args = self._launch_args()
        system_name = platform.system()
        if system_name == "Windows":
            path = self._windows_path()
            if enabled:
                path.parent.mkdir(parents=True, exist_ok=True)
                escaped = " ".join(self._escape_windows_batch_arg(item) for item in launch_args)
                path.write_text(
                    f"@echo off\nstart \"\" {escaped}\n",
                    encoding="utf-8",
                )
            elif path.exists():
                path.unlink()
            return

        if system_name == "Darwin":
            path = self._macos_path()
            if enabled:
                path.parent.mkdir(parents=True, exist_ok=True)
                args_xml = "\n".join(f"    <string>{arg}</string>" for arg in launch_args)
                plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>com.ihdu.login</string>
  <key>ProgramArguments</key>
  <array>
{args_xml}
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
            args = " ".join(f'"{arg}"' for arg in launch_args)
            desktop = f"""[Desktop Entry]
Type=Application
Name=iHDU Login
Exec={args}
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
        font = ImageFont.load_default() if ImageFont else None
        try:
            text_box = draw.textbbox((0, 0), text, font=font)
            text_width = text_box[2] - text_box[0]
            text_height = text_box[3] - text_box[1]
            text_x = (TRAY_ICON_SIZE - text_width) // 2
            text_y = (TRAY_ICON_SIZE - text_height) // 2
        except Exception:
            text_x = TRAY_ICON_SIZE // 2 - 4
            text_y = TRAY_ICON_SIZE // 2 - 6
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
