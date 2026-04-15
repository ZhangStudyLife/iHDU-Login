# IHDU Login

杭电 i-HDU 校园网命令行登录工具。

自动连接 Wi-Fi `i-HDU`，自动认证登录，支持掉线自动重连。

支持 macOS / Windows / Linux。

## 安装依赖

需要 Python 3，先安装依赖：

```bash
pip install -r requirements.txt
```

## 使用方法

### 登录

```bash
python ihdu_cli.py --username 你的学号 --password 你的密码 login
```

如果不希望在命令行里写密码，可以省略 `--password`，脚本会提示你输入（输入时不会显示字符）：

```bash
python ihdu_cli.py --username 你的学号 login
```

如果当前没有连上 `i-HDU`，脚本会自动尝试连接。

### 查询在线状态

```bash
python ihdu_cli.py status
```

### 自动重连

持续监控网络状态，掉线后自动重新登录：

```bash
python ihdu_cli.py --username 你的学号 --password 你的密码 watch
```

默认每 30 秒检测一次，可以用 `--interval` 自定义间隔（单位：秒）：

```bash
python ihdu_cli.py --username 你的学号 --password 你的密码 watch --interval 60
```

按 `Ctrl+C` 停止监控。

## 测试

```bash
python -m unittest discover -s tests -v
```
