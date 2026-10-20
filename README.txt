找货助手 v1.0.0

初版代码基线：后端接口与业务逻辑、飞书适配、165项本地自动化测试。
这不是已通过生产验收的库存系统。版本范围和限制见 RELEASE_1.0.txt。

运行环境
Python >=3.12，使用uv管理。先进入本仓库根目录，执行：
  uv sync --locked
  uv run --locked python main.py
或：
  uv run --locked finding-assistant-api
默认地址：http://127.0.0.1:8001
修改端口：uv run --locked python main.py --port 8002
按Ctrl+C停止。main.py为普通HTTP后端入口，非MCP服务。

检查服务
GET /health/live：200表示HTTP进程存活。
GET /health/ready：默认503，表示尚未装配可信业务后端。
默认启动不开放真实库存读写；任意Bearer字符串不会取得业务权限。
接口文档默认关闭；开发装配时可显式create_app(expose_docs=True)。
当前没有人工操作前端，不能仅凭启动成功就判定完整业务验收完成。

自动化测试
  uv run --locked python run_tests.py
165项测试使用本地受控身份、内存存储及临时文件，不代表真实员工权限、
飞书一致性、实物扫码或线上性能验收。历史结果在reports目录。
部分旧开发辅助脚本为测试依赖保留，不能作为生产入口执行。

目录
finding_assistant/interfaces/http：HTTP接口与参数模型
finding_assistant/application：业务流程、幂等、审计及恢复
finding_assistant/domain：数量与状态规则
finding_assistant/adapters/feishu：飞书HTTP与权限适配
finding_assistant/security：用户登录与业务授权
finding_assistant/infrastructure：状态目录与本机锁
finding_assistant/servers：未来可选MCP适配

配置
没有包含真实密钥、config.local.json、本机状态、虚拟环境和IDE配置。
config.example.json仅为原测试Demo空密钥示例。当前核心仍限制在该测试Demo，
不能仅改示例配置就宣称支持任意生产表。正式装配需完成身份与数据范围校验。
安装部署时应显式设置FINDING_ASSISTANT_STATE_DIR并验证运行权限。
Windows本机锁经过测试；Linux目标服务器及跨主机协调未验收。

交付流程
代码归档 → 真实业务装配与人工验收 → 明确批准后服务器上线。
本次版本归档不执行服务器部署。
