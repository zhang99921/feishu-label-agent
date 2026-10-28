"""接收现有扫码流水并登记 PostgreSQL 内部任务；当前不执行库存过账。"""
import argparse
from collections import Counter
import json
import logging

from finding_assistant.adapters.feishu.base_export import read_scan_export
from finding_assistant.adapters.feishu.existing_forms import ExistingFormsReader, FormsConfig
from finding_assistant.application.intake_worker import run_intake
from finding_assistant.domain.scan_submission import normalize_record
from finding_assistant.infrastructure.environment import read_environment

LOG = logging.getLogger("finding_assistant.intake")


def preview(path, include_blank=False):
    base, table, records = read_scan_export(path)
    counts, errors, warnings = Counter(), Counter(), Counter()
    for record in records:
        counts["observed"] += 1
        submission = normalize_record(base, table, record, include_blank_status=include_blank)
        if submission is None:
            counts["ignored"] += 1
            continue
        counts["blocked" if submission.errors else "eligible_for_intake"] += 1
        counts["unique_box_references"] += len(submission.boxes)
        errors.update(submission.errors)
        warnings.update(submission.warnings)
    return {"mode": "OFFLINE_PREVIEW", "counts": dict(counts), "errors": dict(errors),
            "warnings": dict(warnings), "postgres_written": False, "feishu_written": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    offline = commands.add_parser("preview", help="只读检查 .base 导出，不连接飞书或数据库")
    offline.add_argument("--export", required=True)
    offline.add_argument("--include-blank-status", action="store_true", help="仅预览空状态旧记录，不执行过账")
    performance = commands.add_parser('performance-summary', help='只读汇总HTTP分段耗时，不连接飞书或数据库')
    performance.add_argument('--log-file', default='logs/http.log')
    performance.add_argument('--max-lines', type=int, default=10000)
    performance.add_argument('--request-id', help='按响应X-Request-ID筛选')
    db_init = commands.add_parser("db-init", help="显式创建 PostgreSQL 内部任务表")
    status = commands.add_parser("status", help="查看后台任务数，不代表库存成功数")
    doctor = commands.add_parser('doctor', help='只读检查配置、数据库连接及全部迁移，不访问飞书')
    maintenance = commands.add_parser('db-maintain',help='分批清理过期登录挑战、旧会话和到期审计，不清理业务任务或幂等记录')
    maintenance.add_argument('--audit-days',type=int,default=None,help='默认不清理审计；仅在另行确定期限后显式指定天数')
    poll = commands.add_parser("poll", help="从飞书读取并登记后台任务，不回写库存")
    config_source = poll.add_mutually_exclusive_group()
    config_source.add_argument("--config", help="兼容旧 JSON 配置；优先使用项目 .env")
    config_source.add_argument("--env-file", help="指定 .env，默认当前工作目录的 .env")
    for command in (db_init, status, maintenance, doctor):
        command.add_argument("--env-file", help="指定 .env，默认当前工作目录的 .env")
    poll.add_argument("--watch", action="store_true", help="持续轮询；默认只执行一轮")
    backup = commands.add_parser('backup-pull', help='只读拉取指定飞书表，保存为PostgreSQL版本化副本')
    backup.add_argument('--table-id', action='append', required=True, help='显式指定表ID，可重复；不默认复制整份Base')
    backup_status = commands.add_parser('backup-status', help='查询最近一次完整业务副本，不调用飞书')
    sync = commands.add_parser('sync', help='只读同步配置内的飞书表并原子发布SQL查询版本')
    sync.add_argument('--watch', action='store_true', help='持续同步；默认只执行一轮')
    sync_status = commands.add_parser('sync-status', help='查看SQL日常副本、同步结果与数据时效')
    replica_check = commands.add_parser('replica-check', help='只读巡检SQL活动副本范围、计数和箱索引覆盖，不自动修复')
    replica_check.add_argument('--verify-content', action='store_true', help='另行重算内容摘要并逐字段核对箱索引，耗时高于基础巡检')
    storage = commands.add_parser('backup-storage', help='只读统计副本版本和存储占用，不访问飞书')
    prune = commands.add_parser('backup-prune-preview', help='只读预览指定保留策略，不删除任何版本')
    prune.add_argument('--keep-days', type=int, required=True)
    prune.add_argument('--keep-latest', type=int, required=True)
    prune.add_argument('--limit', type=int, default=50)
    prune.add_argument('--offset', type=int, default=0)
    records = commands.add_parser('replica-records', help='运维直接读取SQL中某张已同步表的原始字段')
    records.add_argument('--table-id', required=True)
    records.add_argument('--limit', type=int, default=20)
    records.add_argument('--after-id')
    for command in (sync, sync_status, records, storage, prune, replica_check):
        command.add_argument('--env-file', help='指定.env，默认当前工作目录的.env')
    boxes = commands.add_parser('find-boxes', help='直接在SQL副本中按箱号、商品或位置检索；仅供运维')
    for command in (backup, backup_status, boxes):
        command.add_argument('--env-file', help='指定.env，默认当前工作目录的.env')
    for command in (backup_status, boxes):
        command.add_argument('--base-token', help='覆盖查询来源；默认使用.env中的FEISHU_APP_TOKEN或Base链接')
    for name in ('box-code', 'fnsku', 'sku', 'po', 'row-code', 'position-code', 'state'):
        boxes.add_argument('--' + name, help='精确匹配；多个筛选条件同时满足')
    boxes.add_argument('--limit', type=int, default=20, help='返回1至100条，默认20条')
    boxes.add_argument('--offset', type=int, default=0)
    inspect = commands.add_parser('inspect', help='运维只读查询，不调用飞书、不修改状态')
    inspections = inspect.add_subparsers(dest='inspection', required=True)
    task_list = inspections.add_parser('tasks', help='按内部状态、来源记录或箱号查接收任务')
    task_detail = inspections.add_parser('task', help='查看单个来源任务的箱号、原因和最近事件')
    writes = inspections.add_parser('writes', help='定位写请求状态与远端记录ID，不自动重发')
    positions = inspections.add_parser('positions', help='只读追踪批次、组合位置及冷却，不释放预占')
    audit = inspections.add_parser('audit', help='查看授权和写入等审计，支持按ID向前分页')
    executions = inspections.add_parser('executions', help='查询库存执行批次进度和待核账原因')
    execution = inspections.add_parser('execution', help='查询逐步执行及逐箱事务，不重发写入')
    rejections = inspections.add_parser('rejections', help='只读查询异常回写回执及关联预占，不调用飞书或重发')
    attention = inspections.add_parser('attention', help='只读汇总待核查执行与处理提示，不自动恢复')
    attention.add_argument('--app-id', help='默认使用.env中的FEISHU_APP_ID')
    attention.add_argument('--base-token', help='可选限定Base，不访问飞书')
    attention.add_argument('--cursor', help='上一页的next_cursor，筛选应用、Base与提醒阈值须保持一致')
    attention.add_argument('--min-age-seconds',type=int,default=300,help='运行/准备任务的提醒阈值，不表示任务已失活')
    rejections.add_argument('--app-id')
    rejections.add_argument('--base-token')
    rejections.add_argument('--record-id', help='飞书来源record_id，不是RK流水号')
    rejections.add_argument('--state', choices=['PENDING', 'RUNNING', 'UNKNOWN', 'REJECTED', 'CONFIRMED'])
    rejections.add_argument('--before-id', help='上一页next_before_id，按回执UUID倒序翻页')
    for command in (task_list, task_detail, writes, positions, audit, executions, execution, rejections, attention):
        command.add_argument('--env-file', help='指定.env，默认当前工作目录的.env')
    for command in (task_list, writes, positions, audit, executions, rejections, attention):
        command.add_argument('--limit', type=int, default=20, help='返回1至100条，默认20条')
    task_list.add_argument('--state', choices=['QUEUED', 'BLOCKED', 'RECONCILE'])
    task_list.add_argument('--record-id', help='飞书来源record_id，不是RK流水号')
    task_list.add_argument('--box-code', help='精确匹配箱号，只查询已接收的内部任务')
    task_detail.add_argument('--source-key', required=True, help='完整的Base:扫码表:record_id来源键')
    writes.add_argument('--state', choices=['PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED', 'UNKNOWN'])
    for command in (writes, positions, audit):
        command.add_argument('--request-key', help='写入请求的UUID4幂等键')
        command.add_argument('--app-id', help='默认使用.env中的FEISHU_APP_ID；未配置时查询所有应用')
    audit.add_argument('--outcome', help='按审计结果精确筛选，例如DENIED、UNKNOWN')
    audit.add_argument('--before-id', type=int, help='接上一页next_before_id，读取更早的审计')
    positions.add_argument('--batch-id', help='后端批次UUID，同一批转仓前后保留')
    positions.add_argument('--base-token', help='按Base过滤，不请求飞书')
    positions.add_argument('--row-code', help='精确匹配目标行码')
    positions.add_argument('--position-code', help='例如--position-code=-01')
    positions.add_argument('--state', choices=['RESERVED', 'RECORDED', 'UNKNOWN', 'OCCUPIED', 'COOLING', 'RELEASED'])
    executions.add_argument('--app-id')
    executions.add_argument('--record-id')
    executions.add_argument('--box-code')
    executions.add_argument('--state', choices=['PREPARED', 'RUNNING', 'RECONCILE', 'SUCCEEDED'])
    execution.add_argument('--source-key', required=True)
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    try:
        if args.command == "preview":
            print(json.dumps(preview(args.export, args.include_blank_status), ensure_ascii=False, indent=2))
            return 0
        if args.command == 'performance-summary':
            from finding_assistant.infrastructure.performance_report import summarize
            print(json.dumps(summarize(args.log_file, max_lines=args.max_lines, request_id=args.request_id), ensure_ascii=False))
            return 0
        from finding_assistant.infrastructure.postgres_tasks import PostgresTasks
        environment = read_environment(args.env_file)
        if args.command in ('sync', 'sync-status', 'replica-records', 'backup-storage', 'backup-prune-preview', 'replica-check'):
            from finding_assistant.infrastructure.business_sync import BusinessSync, SyncConfig
            from finding_assistant.infrastructure.operations_queries import json_scalar
            from finding_assistant.adapters.feishu.existing_forms import parse_base_url
            base = environment.get('FEISHU_APP_TOKEN') or parse_base_url(environment.get('FEISHU_BASE_URL', ''))[0]
            replica = BusinessSync(environment.get('FINDING_ASSISTANT_DATABASE_URL'), base,
                                   SyncConfig.from_values(environment))
            replica.backups.tasks.ready()
            if args.command == 'sync':
                from finding_assistant.adapters.feishu.business_backup_reader import BusinessBackupReader
                from finding_assistant.application.business_sync_worker import run_sync, check_interval
                from finding_assistant.infrastructure.replica_integrity import check_replica
                from finding_assistant.infrastructure.runtime_logging import configure_logging
                from finding_assistant.infrastructure.shutdown import intake_shutdown
                configure_logging('sync', environment)
                check_seconds = check_interval(environment)
                reader = BusinessBackupReader(FormsConfig.from_values(environment))
                try:
                    with intake_shutdown() as stopping:
                        run_sync(replica, reader, watch=args.watch, wait=stopping.wait,
                                 stop_requested=stopping.is_set, check_seconds=check_seconds,
                                 checker=lambda: check_replica(replica, verify_content=True))
                finally:
                    reader.close()
                result = replica.status()
            elif args.command == 'sync-status':
                result = replica.status()
            elif args.command == 'replica-check':
                from finding_assistant.infrastructure.replica_integrity import check_replica
                result = check_replica(replica, verify_content=args.verify_content)
            elif args.command in ('backup-storage', 'backup-prune-preview'):
                from finding_assistant.infrastructure.backup_storage import BackupStorage
                storage = BackupStorage(replica.backups, base)
                result = (storage.status() if args.command == 'backup-storage' else
                          storage.preview(replica.scope_hash, keep_days=args.keep_days, keep_latest=args.keep_latest,
                                          limit=args.limit, offset=args.offset))
            else:
                result = replica.records(args.table_id, limit=args.limit, after_id=args.after_id)
            print(json.dumps(result, ensure_ascii=False, default=json_scalar))
            return 2 if result.get('ready') is False or result.get('healthy') is False else 0
        if args.command in ('backup-pull', 'backup-status', 'find-boxes'):
            from finding_assistant.infrastructure.business_backups import BusinessBackups
            from finding_assistant.infrastructure.operations_queries import json_scalar
            backups = BusinessBackups(environment.get('FINDING_ASSISTANT_DATABASE_URL'))
            backups.tasks.ready()
            if args.command == 'backup-pull':
                from finding_assistant.adapters.feishu.business_backup_reader import BusinessBackupReader
                reader = BusinessBackupReader(FormsConfig.from_values(environment))
                try:
                    result = backups.capture(reader, args.table_id, metadata={'capture_method': 'read_only_feishu_api'})
                finally:
                    reader.close()
            else:
                from finding_assistant.adapters.feishu.existing_forms import parse_base_url
                import re
                base = (args.base_token or environment.get('FEISHU_APP_TOKEN') or
                        parse_base_url(environment.get('FEISHU_BASE_URL', ''))[0])
                if not isinstance(base, str) or not re.fullmatch(r'[A-Za-z0-9_]+', base):
                    raise ValueError('BACKUP_QUERY_BASE_REQUIRED')
                if args.command == 'backup-status':
                    result = backups.status(base)
                else:
                    filters = dict(box_code=args.box_code, fnsku=args.fnsku, sku=args.sku,
                        po=args.po, row_code=args.row_code, position_code=args.position_code,
                        state=args.state, limit=args.limit, offset=args.offset)
                    from finding_assistant.infrastructure.business_sync import BusinessSync, SyncConfig, query_enabled
                    if query_enabled(environment):
                        result = BusinessSync(environment.get('FINDING_ASSISTANT_DATABASE_URL'), base,
                                              SyncConfig.from_values(environment)).boxes(**filters)
                    else:
                        result = backups.boxes(base, **filters)
            print(json.dumps(result, ensure_ascii=False, default=json_scalar))
            return 2 if result.get('found') is False else 0
        if args.command == 'inspect':
            from finding_assistant.infrastructure.operations_queries import OperationsQueries, json_scalar
            queries = OperationsQueries(environment.get('FINDING_ASSISTANT_DATABASE_URL'))
            queries.tasks.ready()
            if args.inspection == 'tasks':
                result = queries.tasks_list(state=args.state, record_id=args.record_id,
                                            box_code=args.box_code, limit=args.limit)
            elif args.inspection == 'task':
                result = queries.task(args.source_key)
            elif args.inspection == 'attention':
                result = queries.attention(app_id=args.app_id if args.app_id is not None else environment.get('FEISHU_APP_ID'),
                    base_token=args.base_token, min_age_seconds=args.min_age_seconds, limit=args.limit, cursor=args.cursor)
            elif args.inspection == 'executions':
                app_id = args.app_id if args.app_id is not None else environment.get('FEISHU_APP_ID') or None
                result = queries.executions(app_id=app_id, record_id=args.record_id, box_code=args.box_code,
                                            state=args.state, limit=args.limit)
                result['app_id_filter'] = app_id
            elif args.inspection == 'execution':
                result = queries.execution(args.source_key)
            elif args.inspection == 'rejections':
                app_id = args.app_id if args.app_id is not None else environment.get('FEISHU_APP_ID') or None
                result = queries.rejections(app_id=app_id, base_token=args.base_token, record_id=args.record_id,
                    state=args.state, before_id=args.before_id, limit=args.limit)
                result['app_id_filter'] = app_id
            else:
                app_id = args.app_id if args.app_id is not None else environment.get('FEISHU_APP_ID') or None
                options = {'app_id': app_id, 'request_key': args.request_key, 'limit': args.limit}
                if args.inspection == 'positions':
                    result = queries.positions(batch_id=args.batch_id, base_token=args.base_token,
                        row_code=args.row_code, position_code=args.position_code, state=args.state, **options)
                else:
                    result = (queries.writes(state=args.state, **options) if args.inspection == 'writes'
                              else queries.audit(outcome=args.outcome, before_id=args.before_id, **options))
                result['app_id_filter'] = app_id
            print(json.dumps(result, ensure_ascii=False, default=json_scalar))
            return 2 if result.get('found') is False else 0
        if args.command == 'doctor':
            from finding_assistant.infrastructure.diagnostics import runtime_diagnostic
            result = runtime_diagnostic(environment)
            print(json.dumps(result, ensure_ascii=False))
            return 0 if result['ready'] else 1
        store = PostgresTasks(environment.get("FINDING_ASSISTANT_DATABASE_URL"))
        if args.command == "db-init":
            store.initialize()
            print(json.dumps({"internal_schema_initialized": True, "feishu_written": False}))
        elif args.command == 'db-maintain':
            from finding_assistant.infrastructure.postgres_operations import PostgresOperations
            operations=PostgresOperations(environment.get('FINDING_ASSISTANT_DATABASE_URL'),
                environment.get('FEISHU_APP_ID') or 'local-maintenance',environment.get('FINDING_ASSISTANT_TOKEN_KEY'))
            print(json.dumps({'maintenance':operations.maintenance(args.audit_days)}))
        elif args.command == "status":
            from finding_assistant.infrastructure.postgres_operations import PostgresOperations
            operations=PostgresOperations(environment.get('FINDING_ASSISTANT_DATABASE_URL'),
                environment.get('FEISHU_APP_ID') or 'local-maintenance',environment.get('FINDING_ASSISTANT_TOKEN_KEY'))
            print(json.dumps({"intake_tasks": store.counts(), "operations":operations.status(), "inventory_posting_enabled": False}))
        elif args.command == "poll":
            from finding_assistant.infrastructure.runtime_logging import configure_logging
            from finding_assistant.infrastructure.shutdown import intake_shutdown
            configure_logging('intake', environment)
            config = FormsConfig.load(args.config) if args.config else FormsConfig.from_env(args.env_file)
            reader = ExistingFormsReader(config)
            try:
                with intake_shutdown() as stopping:
                    LOG.info('intake_status=starting inventory_posting_enabled=false')
                    run_intake(reader, store, watch=args.watch, wait=stopping.wait,
                               stop_requested=stopping.is_set)
            finally:
                try:
                    reader.close()
                finally:
                    LOG.info('intake_status=closed inventory_posting_enabled=false')
        return 0
    except KeyboardInterrupt:
        return 130
    except Exception:
        # 运维日志不得直接打印异常：数据库驱动、HTTP 或 JSON 错误可能含密码/原数据。
        LOG.error("INTAKE_NOT_COMPLETED; check server configuration, source schema and PostgreSQL")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
