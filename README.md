# IHDU Login

适用于杭电 `i-HDU` 校园网的命令行登录脚本，支持：

- 自动连接 Wi-Fi `i-HDU`
- 自动探测门户地址和 `ac_id`
- 终端中文提示
- 掉线后自动重连
- Windows / macOS / Linux 基本适配

## 目录

- [ihdu_cli.py]
- [requirements.txt]
- [tests/test_ihdu_cli.py]

## 安装

先进入目录：

```bash
cd IHDU-login
```

再安装依赖：

```bash
pip install -r requirements.txt
```

如果你是 macOS 自带 Python，建议优先用虚拟环境，避免系统环境里的 `urllib3` / SSL 版本冲突。

## 最常用用法

直接登录：

```bash
python ihdu_cli.py --username 你的学号 --password 你的密码 login
```

持续监控，掉线自动重登：

```bash
python ihdu_cli.py --username 你的学号 --password 你的密码 watch --interval 30
```

查询状态：

```bash
python ihdu_cli.py status
```

如果不想在命令行里明文写密码，也可以只写账号，脚本会在终端里提示输入密码。

## 自动连接 Wi-Fi

在 `login` 和 `watch` 模式下，脚本会先检查当前是否已经联网。

- 如果已经联网，不会重复切换 Wi-Fi
- 如果还没联网，会尝试自动连接 `i-HDU`
- 如果你不想让脚本自动连 Wi-Fi，可以加 `--no-auto-wifi`

默认 SSID 是 `i-HDU`，也可以自己指定：

```bash
python ihdu_cli.py --ssid i-HDU --username 你的学号 --password 你的密码 login
```

平台说明：

- Windows：通过 `netsh wlan` 连接开放 Wi-Fi，并自动创建开放网络配置
- macOS：通过 `networksetup` 连接 Wi-Fi
- Linux：通过 `nmcli` 连接 Wi-Fi

如果 Linux 没装 `nmcli`，脚本会直接给出中文报错。

## 自动探测门户地址

如果你不传 `--base-url` 和 `--ac-id`，脚本会访问常见的联网探测地址，例如：

- `http://www.msftconnecttest.com/connecttest.txt`
- `http://connect.rom.miui.com/generate_204`
- `http://example.com`

然后从重定向页面或 meta refresh 中提取真正的门户地址和 `ac_id`。

如果你想禁用自动探测，可以显式指定：

```bash
python ihdu_cli.py --base-url https://login.hdu.edu.cn --ac-id 32 --username 你的学号 --password 你的密码 login
```

或者：

```bash
python ihdu_cli.py --no-auto-detect --base-url http://192.168.112.30 --ac-id 32 --username 你的学号 --password 你的密码 login
```

## 本次实测结论

在开发板 `10.252.102.104` 上，2026-04-02 的实测结果是：

- 未认证时，外部 HTTP 请求会跳到：`http://192.168.112.30/index_32.html`
- 自动探测得到的结果是：`http://192.168.112.30` + `ac_id=32`
- 显式指定 `http://192.168.112.30 --ac-id 32` 可以成功登录
- 显式指定 `https://login.hdu.edu.cn --ac-id 32` 也实测可以成功登录

实际建议：

- 最稳的是让脚本自动探测
- 如果你要手工写死，当前环境优先写 `--ac-id 32`
- `base_url` 用 `http://192.168.112.30` 或 `https://login.hdu.edu.cn` 都可以

## 输出模式

默认输出中文摘要，例如：

```text
登录成功，账号：23062118，IP：10.252.xx.xx，网关返回：login_ok
实际使用的门户地址：http://192.168.112.30，ac_id：32
```

如果你想看原始 JSON：

```bash
python ihdu_cli.py --json --username 你的学号 --password 你的密码 login
```

## 环境变量

也可以通过环境变量传参：

```bash
IHDU_USERNAME=你的学号
IHDU_PASSWORD=你的密码
IHDU_SSID=i-HDU
IHDU_BASE_URL=https://login.hdu.edu.cn
IHDU_AC_ID=32
```

常用环境变量：

- `IHDU_USERNAME`
- `IHDU_PASSWORD`
- `IHDU_SSID`
- `IHDU_BASE_URL`
- `IHDU_AC_ID`
- `IHDU_TIMEOUT`
- `IHDU_INTERVAL`

## 测试

运行本地测试：

```bash
python -m unittest discover -s tests -v
```

## 安全提醒

你前面已经把校园网密码发到聊天里了。既然脚本已经跑通，建议尽快修改校园网密码，不要长期继续使用已经泄露过的口令。
