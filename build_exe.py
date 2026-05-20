import subprocess
import sys
from pathlib import Path


def main() -> int:
    project_root = Path(__file__).resolve().parent
    entry = project_root / "ihdu_cli.py"
    if not entry.exists():
        print("未找到入口文件 ihdu_cli.py。", file=sys.stderr)
        return 1

    command = [
        sys.executable,
        "-m",
        "pyinstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--name",
        "iHDU-Login",
        "--collect-submodules",
        "keyring",
        "--collect-submodules",
        "pystray",
        "--collect-submodules",
        "PIL",
        str(entry),
    ]

    try:
        subprocess.run(command, check=True)
    except FileNotFoundError:
        print("未找到 PyInstaller，请先执行: pip install -r requirements-build.txt", file=sys.stderr)
        return 1
    except subprocess.CalledProcessError as exc:
        return exc.returncode

    output = project_root / "dist" / ("iHDU-Login.exe" if sys.platform.startswith("win") else "iHDU-Login")
    print(f"打包完成: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
