# 项目运行入口：调用 HTTP 启动器；PyCharm 可直接运行此文件，默认端口为 8001。
"""Start the ordinary HTTP backend. Run with uv run python main.py."""
from finding_assistant.interfaces.http.__main__ import main

if __name__ == "__main__":
    main()
