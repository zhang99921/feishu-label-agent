"""现有一表三单的后台入口。先运行 python worker.py preview --export 文件.base。"""
from finding_assistant.interfaces.worker.__main__ import main

if __name__ == "__main__":
    raise SystemExit(main())
