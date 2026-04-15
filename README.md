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

## 使用

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

## 常见问题

**Q: 提示"未获取到本机 IP"**

A: 设备未连上 `i-HDU`，且脚本自动连接失败。请手动连接 Wi-Fi 后重试。

**Q: Linux 下提示找不到 `nmcli`**

A: 需要安装 NetworkManager：`sudo apt install network-manager`

**Q: 登录失败，返回 error**

A: 检查学号和密码是否正确，确认当前连的是 `i-HDU` 而非其他网络。

## 工作原理

脚本模拟了 i-HDU 认证门户的登录流程：获取 challenge token → HMAC-MD5 加密密码 → SRBX1 编码 → 提交认证。全程 JSONP 通信，与浏览器行为一致。

## License

MIT
