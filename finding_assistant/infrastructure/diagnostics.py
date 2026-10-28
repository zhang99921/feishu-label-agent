"""后台只读诊断；不访问飞书、不修改数据库，也不显示配置值或原始异常。"""
import psycopg

from .postgres_tasks import PostgresTasks
from .preflight import configuration_report


def runtime_diagnostic(environment):
    config = configuration_report(environment)
    database = {'status': 'unavailable', 'code': 'DATABASE_UNAVAILABLE'}
    try:
        PostgresTasks(environment.get('FINDING_ASSISTANT_DATABASE_URL')).ready()
        database = {'status': 'ready', 'code': 'DATABASE_MIGRATIONS_VERIFIED'}
    except psycopg.errors.UndefinedTable:
        database['code'] = 'DATABASE_SCHEMA_NOT_READY'
    except ValueError as error:
        # 仅允许本项目定义的固定错误码，禁止输出驱动异常或连接配置。
        code = str(error)
        database['code'] = code if code in {
            'DATABASE_URL_REQUIRED', 'DATABASE_MIGRATION_REQUIRED', 'MIGRATION_CHECKSUM_MISMATCH'
        } else 'INVALID_DATABASE_CONFIGURATION'
    except psycopg.Error:
        pass
    return {'ready': config['valid'] and database['status'] == 'ready',
            'configuration': config, 'postgresql': database,
            'feishu_checked': False, 'inventory_posting_enabled': False}
