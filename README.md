<div align="center">

# iHDU Login

杭电校园网命令行登录工具

告别浏览器认证页面，一条命令搞定 i-HDU

**自动连 WiFi · 自动登录 · 掉线自动重连**

macOS / Windows / Linux 全平台支持

</div>

---

## 安装

需要 Python 3，克隆仓库后安装依赖：

```bash
git clone https://github.com/chenhaoCRT/iHDU-Login.git
cd iHDU-Login
pip install -r requirements.txt
```

如需本地打包 EXE，再安装构建依赖：

```bash
pip install -r requirements-build.txt
```

## 模块结构

项目已拆分为多脚本模块化管理：

- `ihdu_login/common.py`：核心认证流程（challenge / 加密 / 登录 / 状态 / Wi-Fi）
- `ihdu_login/ui.py`：桌面 UI、凭据存储、后台轮询、托盘、自启
- `ihdu_login/cli.py`：命令行参数与子命令分发
- `ihdu_cli.py`：兼容入口（薄封装）

## 使用

### 可视化 UI（推荐）

首次输入账号密码后可自动保存配置，后台轮询检测并自动认证，支持手动“立即重连”。

```bash
python ihdu_cli.py ui
```

静默后台启动（适合开机自启）：

```bash
python ihdu_cli.py ui --headless
```

UI 特性：

- 轻量 `tkinter + ttk` 界面，低资源占用
- 账号、轮询间隔、开机自启配置持久化
- 密码优先写入系统钥匙串；不可用时回退本地加密存储（不明文落盘）
- 后台线程自动检测在线状态，离线自动认证
- 支持关闭窗口后最小化到托盘继续运行

### 登录

```bash
python ihdu_cli.py --username 你的学号 --password 你的密码 login
```

不放心在命令行里写密码？省略 `--password`，脚本会安全地提示你输入：

```bash
python ihdu_cli.py --username 你的学号 login
```

> 如果当前没有连上 `i-HDU`，脚本会自动帮你连接 Wi-Fi。

### 查询状态

```bash
python ihdu_cli.py status
```

### 自动重连

持续监控网络，掉线了自动重新登录，不用再操心：

```bash
python ihdu_cli.py --username 你的学号 --password 你的密码 watch
```

默认每 30 秒检测一次，用 `--interval` 自定义间隔（秒）：

```bash
# 每 60 秒检测一次
python ihdu_cli.py --username 你的学号 --password 你的密码 watch --interval 60
```

按 `Ctrl + C` 随时停止。

### 命令总览

```bash
python ihdu_cli.py {status,login,watch,ui} -h
```

## 常见问题

**Q: 提示"未获取到本机 IP"**

A: 设备未连上 `i-HDU`，且脚本自动连接失败。请手动连接 Wi-Fi 后重试。

**Q: Linux 下提示找不到 `nmcli`**

A: 需要安装 NetworkManager：`sudo apt install network-manager`

**Q: 登录失败，返回 error**

A: 检查学号和密码是否正确，确认当前连的是 `i-HDU` 而非其他网络。

**Q: UI 里密码会明文保存吗？**

A: 不会。程序优先保存到系统钥匙串（`keyring`）；钥匙串不可用时才回退本地加密存储。

**Q: 托盘功能不可用怎么办？**

A: 请确认已安装 `pystray` 和 `Pillow`，并且系统桌面环境支持托盘图标。

**Q: 能不能给不装 Python 的同学直接使用？**

A: 可以。你可以在 Windows 上打包 EXE 后分发：

```bash
python build_exe.py
```

打包完成后可执行文件位于 `dist/iHDU-Login.exe`。

## 工作原理

脚本模拟了 i-HDU 认证门户的登录流程：获取 challenge token → HMAC-MD5 加密密码 → SRBX1 编码 → 提交认证。全程 JSONP 通信，与浏览器行为一致。

## License

MIT
