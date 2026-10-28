"""统一读取 .env；系统环境变量优先，不执行脚本或展开配置中的变量引用。"""
import os
from pathlib import Path

from dotenv import dotenv_values


def read_environment(path=None):
    explicit = path is not None
    path = Path(path) if explicit else Path.cwd() / ".env"
    if explicit and not path.is_file():
        raise ValueError("ENV_FILE_NOT_FOUND")
    values = dotenv_values(path, encoding="utf-8-sig", interpolate=False) if path.is_file() else {}
    # 不改动全局环境，因此不同配置实例和测试之间不会相互污染。
    return {**{k: v for k, v in values.items() if v is not None}, **os.environ}


def apply_environment(path=None):
    """仅供 HTTP 启动器在加载应用模块之前使用，不覆盖已注入的服务器环境。"""
    for key, value in read_environment(path).items():
        if key.startswith(("FEISHU_", "FINDING_ASSISTANT_")):
            os.environ.setdefault(key, value)


def env_bool(values, key, default=False):
    value = values.get(key)
    if value is None:
        return default
    if value.lower() not in ("true", "false", "1", "0"):
        raise ValueError("INVALID_BOOLEAN_CONFIGURATION")
    return value.lower() in ("true", "1")
