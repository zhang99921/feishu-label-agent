"""显式启用的扫码应用装配；不读取旧实验配置，不自动连接测试 Demo。"""
from urllib.parse import urlsplit

from finding_assistant.infrastructure.environment import read_environment, env_bool
from finding_assistant.infrastructure.preflight import require_configuration
from finding_assistant.adapters.feishu.existing_forms import FormsConfig, ExistingFormsReader
from finding_assistant.adapters.feishu.scan_access import NativeScanAccess
from finding_assistant.application.scan_service import ScanService
from finding_assistant.security.login import LoginService, OAuthProvider, session_duration
from finding_assistant.security.native_access import NativePermissionGate
from finding_assistant.infrastructure.postgres_operations import PostgresOperations
from finding_assistant.infrastructure.transfer_reservations import TransferReservations
from finding_assistant.infrastructure.position_reservations import PositionReservations
from finding_assistant.adapters.feishu.business_tables import BusinessTableConfig,BusinessTableReader
from .app import create_app


def configured_app():
    env = read_environment()
    require_configuration(env)
    if not env_bool(env, 'FINDING_ASSISTANT_ENABLE_SCAN_API'):
        return create_app()
    config = FormsConfig.from_values(env)
    tables = BusinessTableConfig.from_env(env)
    tenant = env.get('FEISHU_TENANT_KEY', '').strip()
    redirect = env.get('FEISHU_OAUTH_REDIRECT_URI', '').strip()
    if not tenant or urlsplit(redirect).path != '/auth/feishu/callback':
        raise ValueError('TENANT_AND_CALLBACK_CONFIG_REQUIRED')
    store = PostgresOperations(env.get('FINDING_ASSISTANT_DATABASE_URL'),config.app_id,
                              env.get('FINDING_ASSISTANT_TOKEN_KEY'))
    store.ready()  # 启动只检查迁移，建表仍须显式 db-init。
    if not config.app_token:
        from dataclasses import replace
        reader = ExistingFormsReader(config)
        try:
            reader.login()
            config = replace(config, app_token=reader.app_token)
        finally:
            reader.close()
    access = NativeScanAccess(config)
    provider = OAuthProvider(config.app_id, config.app_secret)
    login = LoginService(provider, redirect, scopes=('auth:user.id:read','bitable:app','offline_access'),
                         store=store,session_seconds=session_duration(env))
    reader = BusinessTableReader(access,tables) if tables is not None else None
    allocate = (env_bool(env, 'FINDING_ASSISTANT_ENABLE_POSITION_ALLOCATION') or
                env_bool(env, 'FINDING_ASSISTANT_ENABLE_TRANSFER_ALLOCATION'))
    # 旧开关作为兼容别名也装配新模型；旧表仅用于原请求重放和占用隔离。
    reservations = (TransferReservations(store, config.app_token, config.scan_table_id, tables.row_table_id)
                    if allocate else None)
    positions = (PositionReservations(store, config.app_token, config.scan_table_id,
                                     tables.box_table_id, tables.row_table_id) if allocate else None)
    service = ScanService(NativePermissionGate(login, access, tenant,audit=store), access,
                          journal=store,business_reader=reader,transfer_reservations=reservations,
                          position_reservations=positions)
    if env_bool(env, 'FINDING_ASSISTANT_ENABLE_SQL_QUERY'):
        from finding_assistant.infrastructure.business_sync import BusinessSync, SyncConfig
        from finding_assistant.application.sql_inventory_query import SqlInventoryQuery
        from finding_assistant.adapters.feishu.sql_visibility import NativeVisibilityDirectory
        replica = BusinessSync(env.get('FINDING_ASSISTANT_DATABASE_URL'), config.app_token,
                               SyncConfig.from_values(env))
        visibility = (NativeVisibilityDirectory(access, env.get('FEISHU_SQL_DEFAULT_ROLE_ID', '').strip())
                      if env_bool(env, 'FINDING_ASSISTANT_ENABLE_SQL_VISIBILITY') else None)
        service.sql_query = SqlInventoryQuery(service.gate, replica, env.get('FEISHU_BOX_TABLE_ID'),
            visibility_directory=visibility,
            row_table_id=env.get('FEISHU_ROW_TABLE_ID'), app_id=config.app_id, journal=store,
            detail_tables={'flows':config.scan_table_id,'details':env.get('FEISHU_BOX_DETAILS_TABLE_ID'),
                           'ledger':env.get('FEISHU_TRANSACTION_TABLE_ID')})
    if env_bool(env, 'FINDING_ASSISTANT_ENABLE_INVENTORY_EXECUTION'):
        from finding_assistant.adapters.feishu.inventory_access import InventoryAccess
        from finding_assistant.infrastructure.inventory_execution_store import InventoryExecutionStore
        from finding_assistant.application.inventory_execution import InventoryExecution
        service.inventory_execution = InventoryExecution(service.gate, InventoryAccess(access, tables),
            InventoryExecutionStore(store, config.app_token, config.scan_table_id,
                                    tables.box_table_id, tables.row_table_id), positions)
        from finding_assistant.application.background_inventory import BackgroundInventory
        service.background_inventory = BackgroundInventory(service.inventory_execution)
        from finding_assistant.infrastructure.warehouse_tasks import WarehouseTaskStore
        from finding_assistant.application.warehouse_tasks import WarehouseTasks
        service.warehouse_tasks = WarehouseTasks(service, login, WarehouseTaskStore(store, config.app_token))


    def close():
        try:
            task_worker = getattr(service, 'warehouse_tasks', None)
            if task_worker is not None: task_worker.close()
            dispatcher = getattr(service, 'background_inventory', None)
            if dispatcher is not None:
                dispatcher.close()
        finally:
            try:
                access.close()
            finally:
                provider.close()

    return create_app(scan_service=service, scan_login=login, on_shutdown=close,
                      readiness_check=store.ready, rejection_audit=store.audit_http_rejection)
