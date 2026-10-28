"""离线运行配置检查；只返回配置名和固定错误码，不连接或修改外部服务。"""
from cryptography.fernet import Fernet
import psycopg
from psycopg.conninfo import conninfo_to_dict

from finding_assistant.adapters.feishu.existing_forms import FormsConfig
from finding_assistant.adapters.feishu.business_tables import BusinessTableConfig
from finding_assistant.infrastructure.environment import env_bool
from finding_assistant.infrastructure.runtime_logging import LogConfig, LOG_KEYS
from finding_assistant.security.login import AuthenticationError, validate_redirect_uri, session_duration


def configuration_report(values):
    report = {'valid': False, 'mode': 'SCAN_API', 'configuration_only': True,
              'dependencies_checked': False, 'inventory_posting_enabled': False,
              'missing_keys': [], 'checks': []}

    def add(name, valid, code, keys=()):
        report['checks'].append({'name': name, 'status': 'ok' if valid else 'invalid',
                                 'code': code, 'keys': list(keys)})

    try:
        session_duration(values)
        add('session_duration', True, 'CONFIGURED')
    except (ValueError, TypeError):
        add('session_duration', False, 'INVALID_SESSION_DURATION', ['FINDING_ASSISTANT_SESSION_SECONDS'])

    try:
        LogConfig.from_values(values)
        add('runtime_logs', True, 'CONFIGURED')
    except ValueError:
        add('runtime_logs', False, 'INVALID_RUNTIME_LOG_CONFIGURATION', LOG_KEYS)

    from finding_assistant.application.business_sync_worker import check_interval
    try:
        check_interval(values)
        add('replica_check_schedule', True, 'CONFIGURED')
    except ValueError:
        add('replica_check_schedule', False, 'INVALID_REPLICA_CHECK_INTERVAL',
            ['FINDING_ASSISTANT_REPLICA_CHECK_SECONDS'])

    try:
        enabled = env_bool(values, 'FINDING_ASSISTANT_ENABLE_SCAN_API')
        sql_enabled = env_bool(values, 'FINDING_ASSISTANT_ENABLE_SQL_QUERY')
        visibility_enabled = env_bool(values, 'FINDING_ASSISTANT_ENABLE_SQL_VISIBILITY')
        transfer_enabled = env_bool(values, 'FINDING_ASSISTANT_ENABLE_TRANSFER_ALLOCATION')
        position_enabled = env_bool(values, 'FINDING_ASSISTANT_ENABLE_POSITION_ALLOCATION')
        posting_enabled = env_bool(values, 'FINDING_ASSISTANT_ENABLE_INVENTORY_EXECUTION')
    except (ValueError, AttributeError):
        add('scan_api', False, 'INVALID_BOOLEAN_CONFIGURATION', ['FINDING_ASSISTANT_ENABLE_SCAN_API'])
        return report
    if transfer_enabled and not enabled:
        add('transfer_allocation', False, 'TRANSFER_REQUIRES_SCAN_API',
            ['FINDING_ASSISTANT_ENABLE_TRANSFER_ALLOCATION', 'FINDING_ASSISTANT_ENABLE_SCAN_API'])
    if position_enabled and not enabled:
        add('position_allocation', False, 'POSITION_REQUIRES_SCAN_API',
            ['FINDING_ASSISTANT_ENABLE_POSITION_ALLOCATION', 'FINDING_ASSISTANT_ENABLE_SCAN_API'])
    if posting_enabled and (not enabled or not (position_enabled or transfer_enabled)):
        add('inventory_execution', False, 'POSTING_REQUIRES_SCAN_AND_POSITION_ALLOCATION',
            ['FINDING_ASSISTANT_ENABLE_SCAN_API', 'FINDING_ASSISTANT_ENABLE_POSITION_ALLOCATION'])
    if visibility_enabled and not sql_enabled:
        add('sql_visibility', False, 'VISIBILITY_REQUIRES_SQL_QUERY',
            ['FINDING_ASSISTANT_ENABLE_SQL_QUERY', 'FINDING_ASSISTANT_ENABLE_SQL_VISIBILITY'])
    if sql_enabled:
        from finding_assistant.infrastructure.business_sync import SyncConfig
        try:
            sync = SyncConfig.from_values(values)
            if not enabled or values.get('FEISHU_BOX_TABLE_ID') not in sync.table_ids:
                raise ValueError
            if values.get('FEISHU_ROW_TABLE_ID') not in sync.table_ids:
                raise ValueError
            import re
            default_role = values.get('FEISHU_SQL_DEFAULT_ROLE_ID', '').strip()
            if default_role and not re.fullmatch(r'[A-Za-z0-9]+', default_role):
                raise ValueError
            add('sql_query', True, 'CONFIGURED_NATIVE_VISIBILITY' if visibility_enabled else 'CONFIGURED_ADMIN_SCOPE_ONLY')
        except ValueError:
            add('sql_query', False, 'SQL_QUERY_REQUIRES_LOGIN_BOX_AND_EXPLICIT_SYNC_SCOPE',
                ['FINDING_ASSISTANT_ENABLE_SCAN_API', 'FEISHU_SYNC_TABLE_IDS', 'FEISHU_BOX_TABLE_ID'])
    if not enabled:
        report.update(valid=all(c['status'] == 'ok' for c in report['checks']), mode='HTTP_ONLY')
        add('scan_api', True, 'SCAN_API_DISABLED')
        return report

    required = ('FEISHU_APP_ID', 'FEISHU_APP_SECRET', 'FEISHU_TENANT_KEY',
                'FEISHU_OAUTH_REDIRECT_URI', 'FINDING_ASSISTANT_DATABASE_URL',
                'FINDING_ASSISTANT_TOKEN_KEY')
    report['missing_keys'] = [key for key in required if not str(values.get(key) or '').strip()]

    try:
        FormsConfig.from_values(values)
        add('feishu_target', True, 'CONFIGURED')
    except (ValueError, TypeError, AttributeError):
        add('feishu_target', False, 'INVALID_FEISHU_CONFIGURATION',
            ['FEISHU_APP_ID', 'FEISHU_APP_SECRET', 'FEISHU_BASE_URL', 'FEISHU_APP_TOKEN',
             'FEISHU_SCAN_TABLE_ID', 'FEISHU_POLL_SECONDS', 'FEISHU_INCLUDE_BLANK_STATUS'])

    try:
        uri = validate_redirect_uri(values.get('FEISHU_OAUTH_REDIRECT_URI', ''))
        if not values.get('FEISHU_TENANT_KEY', '').strip() or uri.path != '/auth/feishu/callback':
            raise ValueError
        add('oauth', True, 'CONFIGURED')
    except (AuthenticationError, ValueError, AttributeError):
        add('oauth', False, 'INVALID_TENANT_OR_CALLBACK', ['FEISHU_TENANT_KEY', 'FEISHU_OAUTH_REDIRECT_URI'])

    try:
        dsn = values.get('FINDING_ASSISTANT_DATABASE_URL', '')
        if not isinstance(dsn, str) or not dsn.strip():
            raise ValueError
        conninfo_to_dict(dsn)  # 只解析语法，不探测网络、不输出连接信息。
        add('postgresql', True, 'CONFIGURED')
    except (psycopg.Error, ValueError, TypeError):
        add('postgresql', False, 'INVALID_DATABASE_CONFIGURATION', ['FINDING_ASSISTANT_DATABASE_URL'])

    try:
        Fernet(values.get('FINDING_ASSISTANT_TOKEN_KEY'))
        add('session_encryption', True, 'CONFIGURED')
    except (ValueError, TypeError):
        add('session_encryption', False, 'INVALID_TOKEN_ENCRYPTION_KEY', ['FINDING_ASSISTANT_TOKEN_KEY'])

    try:
        business = BusinessTableConfig.from_env(values)
        add('business_tables', True, 'CONFIGURED' if business else 'NOT_CONFIGURED_OPTIONAL')
        if transfer_enabled:
            add('transfer_allocation', business is not None, 'CONFIGURED' if business else 'TRANSFER_REQUIRES_BUSINESS_TABLES',
                ['FEISHU_BOX_TABLE_ID', 'FEISHU_ROW_TABLE_ID'])
        if position_enabled:
            add('position_allocation', business is not None, 'CONFIGURED' if business else 'POSITION_REQUIRES_BUSINESS_TABLES',
                ['FEISHU_BOX_TABLE_ID', 'FEISHU_ROW_TABLE_ID'])
        if posting_enabled:
            complete = business is not None and bool(business.transaction_table_id and business.details_table_id)
            add('inventory_tables', complete, 'CONFIGURED' if complete else 'POSTING_REQUIRES_LEDGER_AND_DETAILS',
                ['FEISHU_TRANSACTION_TABLE_ID', 'FEISHU_BOX_DETAILS_TABLE_ID'])
    except (ValueError, TypeError, AttributeError):
        add('business_tables', False, 'INVALID_BUSINESS_TABLE_CONFIGURATION',
            ['FEISHU_BOX_TABLE_ID', 'FEISHU_ROW_TABLE_ID', 'FEISHU_TRANSACTION_TABLE_ID'])
    report['valid'] = not report['missing_keys'] and all(c['status'] == 'ok' for c in report['checks'])
    report['inventory_posting_enabled'] = posting_enabled and report['valid']
    return report


def require_configuration(values):
    report = configuration_report(values)
    if not report['valid']:
        codes = [c['code'] for c in report['checks'] if c['status'] != 'ok']
        raise ValueError('SCAN_CONFIGURATION_INVALID: ' + ','.join(codes))
    return report
