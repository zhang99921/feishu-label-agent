# 共享状态目录：保存本地配置、表映射、请求令牌、审计队列和锁文件，库存仍保存在飞书。
# 同一主机的合作进程必须使用相同目录；安装部署时显式配置 FINDING_ASSISTANT_STATE_DIR。
"""All cooperating local server processes must use the SAME state directory.

The source-checkout default preserves existing experiment files. Installed
deployments must explicitly configure FINDING_ASSISTANT_STATE_DIR; this does
not provide distributed locking or a new inventory database.
"""
import os
from pathlib import Path

STATE_DIR = Path(os.environ.get("FINDING_ASSISTANT_STATE_DIR",Path(__file__).resolve().parents[2])).resolve()
