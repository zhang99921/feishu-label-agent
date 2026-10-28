# 普通后端启动器：uv run python main.py，默认只监听本机 127.0.0.1:8001。
# 使用单 worker；扫码启用时使用PostgreSQL会话与幂等，库存执行仍需后续接入。
"""Start one ordinary HTTP backend; no automatic Feishu inventory wiring."""
import argparse
import json

import uvicorn

from finding_assistant.infrastructure.environment import apply_environment, read_environment
from finding_assistant.infrastructure.runtime_logging import configure_logging


# 解析启动参数、配置脱敏请求日志，再通过 create_app 工厂启动 Uvicorn。
def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--host",default="127.0.0.1")
    parser.add_argument("--port",type=int,default=8001)
    parser.add_argument("--env-file", help="服务端 .env 配置，默认读取当前工作目录的 .env")
    parser.add_argument("--check-config", action="store_true", help="只读检查配置并退出；不启动服务、不连接飞书或数据库")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be in 1..65535")
    if args.check_config:
        from finding_assistant.infrastructure.preflight import configuration_report
        try:
            report = configuration_report(read_environment(args.env_file))
        except (ValueError, OSError):
            report = {'valid': False, 'configuration_only': True, 'code': 'ENV_FILE_UNAVAILABLE'}
        print(json.dumps(report, ensure_ascii=False))
        parser.exit(0 if report['valid'] else 2)
    try:
        apply_environment(args.env_file)
    except (ValueError, OSError):
        parser.exit(2, 'ENV_FILE_UNAVAILABLE\n')
    try:
        logger = configure_logging('http', read_environment(args.env_file))
    except (ValueError, OSError):
        parser.exit(2, 'RUNTIME_LOG_CONFIGURATION_OR_STORAGE_INVALID\n')
    logger.info('http_status=starting')
    try:
        uvicorn.run("finding_assistant.interfaces.http.runtime:configured_app",factory=True,
            host=args.host,port=args.port,workers=1,access_log=False,proxy_headers=False)
    finally:
        logger.info('http_status=stopped')


if __name__ == "__main__":
    main()
