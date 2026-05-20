import argparse
import getpass
import sys

from .common import DEFAULT_INTERVAL, IHDUClient, summarize_login, summarize_status
from .ui import run_ui


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
        password = args.password or getpass.getpass("请输入校园网密码: ").strip()
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
