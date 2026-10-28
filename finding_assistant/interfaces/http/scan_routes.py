"""扫码 HTTP 入口；Cookie 保存不透明会话ID，绝不把飞书令牌返回给浏览器。"""
import secrets
import json
from typing import Annotated, Literal

from fastapi import APIRouter, Header, HTTPException, Path, Query, Request
from fastapi.responses import JSONResponse, RedirectResponse
from pydantic import BaseModel, ConfigDict, Field

from finding_assistant.security.login import AuthenticationError
from finding_assistant.application.inbound_validation import InboundValidationService
from .schemas import Text
from finding_assistant.infrastructure.warehouse_tasks import TaskQueueFull


class ScanFields(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    fields: dict[str, str]


class TransferFields(ScanFields):
    target_warehouse: Literal['优福斯仓', '欣源仓'] | None = None


class InboundFields(ScanFields):
    target_warehouse: Literal['优福斯仓', '欣源仓'] | None = None


class WarehouseTask(TransferFields):
    action: Literal['IN','OUT','MOVE']


class ReviewedTask(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    review_fingerprint: Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]


class InboundPreview(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)
    box_codes: Annotated[list[Text], Field(min_length=1,max_length=36)]
    location_code: Text
    warehouse: Text


def scan_router(service, login):
    router = APIRouter()
    secure = login.redirect_uri.startswith('https://')

    def cookie_value(request, name):
        # 会话/CSRF/登录绑定均由本服务生成，不允许重复Cookie被解析器静默覆盖。
        count = sum(1 for raw in request.headers.getlist('cookie') for part in raw.split(';')
                    if part.partition('=')[0].strip() == name)
        if count > 1:
            raise AuthenticationError('ambiguous login cookies')
        return request.cookies.get(name)

    def sid(request):
        # Bearer 会话供 API 客户端使用；浏览器写入必须同时提供 CSRF 值。
        headers = request.headers.getlist('authorization')
        if headers:
            if len(headers) != 1:
                raise AuthenticationError('invalid session header')
            scheme, sep, token = headers[0].partition(' ')
            if scheme.lower() != 'bearer' or not sep or not token or len(token)>512 or any(c.isspace() for c in token):
                raise AuthenticationError('invalid session header')
            return token
        value = cookie_value(request, 'scan_session')
        if not value or len(value)>512 or not value.isascii() or any(c.isspace() or ord(c)<33 or ord(c)==127 for c in value):
            raise AuthenticationError('login required')
        if request.method == 'POST':
            cookie, header = cookie_value(request, 'scan_csrf') or '', request.headers.get('x-csrf-token', '')
            if (len(request.headers.getlist('x-csrf-token')) != 1 or not 32 <= len(cookie) <= 512
                    or not 32 <= len(header) <= 512 or not cookie.isascii() or not header.isascii()
                    or not secrets.compare_digest(cookie, header)):
                raise HTTPException(403)
        return value

    @router.get('/auth/feishu/start')
    def start(ui: bool = False):
        binding = secrets.token_urlsafe(32)
        response = RedirectResponse(login.begin(binding), status_code=302)
        response.set_cookie('scan_login_binding', binding, max_age=300, httponly=True, secure=secure, samesite='lax')
        if ui:
            response.set_cookie('scan_ui_return', 'app', max_age=300, httponly=True, secure=secure, samesite='lax')
        else:
            response.delete_cookie('scan_ui_return')
        return response

    @router.get('/auth/feishu/callback')
    def callback(request: Request):
        if any(len(request.query_params.getlist(k)) != 1 for k in request.query_params):
            raise AuthenticationError('duplicate callback parameters')
        session_id = login.finish(request.query_params.get('state',''), cookie_value(request, 'scan_login_binding') or '',
                                  request.query_params.get('code',''), request.query_params.get('error'))
        response = RedirectResponse('/app' if cookie_value(request, 'scan_ui_return') == 'app' else '/api/v1/access/me', status_code=303)
        response.delete_cookie('scan_login_binding')
        response.delete_cookie('scan_ui_return')
        response.set_cookie('scan_session', session_id, max_age=login.session_seconds, httponly=True, secure=secure, samesite='lax')
        response.set_cookie('scan_csrf', secrets.token_urlsafe(32), max_age=login.session_seconds, secure=secure, samesite='strict')
        return response

    @router.get('/api/v1/access/me')
    def me(request: Request):
        identity = service.gate.authorize(sid(request), 'QUERY')
        return {'data': {'open_id':identity.open_id, 'role':identity.role, 'permission':identity.permission}}

    @router.post('/auth/logout')
    def logout(request: Request):
        login.logout(sid(request))
        response = JSONResponse({'logged_out':True})
        response.delete_cookie('scan_session')
        response.delete_cookie('scan_csrf')
        return response

    @router.get('/api/v1/scans')
    def query(request: Request, page_token: Annotated[str | None, Query(max_length=2000)] = None):
        return {'data':service.query(sid(request), page_token)}

    def sql_query():
        query = getattr(service, 'sql_query', None)
        if query is None:
            raise HTTPException(503)
        return query

    def sql_result(result):
        from finding_assistant.infrastructure.operations_queries import json_scalar
        # 数量保留十进制精度；UUID与UTC时间也按稳定文本格式返回。
        return {'data': json.loads(json.dumps(result, default=json_scalar, ensure_ascii=False))}

    @router.get('/api/v1/search/access')
    def search_access(request: Request):
        return {'data':sql_query().readiness(sid(request))}

    @router.get('/api/v1/search/boxes')
    def search_boxes(request: Request,
                     box_code: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
                     fnsku: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
                     sku: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
                     po: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
                     row_code: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
                     position_code: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
                     state: Annotated[str | None, Query(min_length=1, max_length=200)] = None,
                     limit: Annotated[int, Query(ge=1, le=100)] = 20,
                     offset: Annotated[int, Query(ge=0, le=1000000)] = 0,
                     visibility_token: Annotated[str | None, Query(pattern=r'^[0-9a-f]{64}$')]=None):
        try:
            result = sql_query().boxes(sid(request), box_code=box_code, fnsku=fnsku, sku=sku, po=po,
                row_code=row_code, position_code=position_code, state=state, limit=limit, offset=offset,visibility_token=visibility_token)
        except ValueError:
            raise HTTPException(422) from None
        return sql_result(result)

    @router.get('/api/v1/sync/status')
    def sql_status(request: Request):
        return sql_result(sql_query().status(sid(request)))

    @router.get('/api/v1/search/boxes/{record_id}')
    def box_details(request: Request,
                    record_id: Annotated[str,Path(min_length=1,max_length=200,pattern=r'^[A-Za-z0-9]+$')],
                    section: Literal['all','box','details','flows','ledger']='all',
                    limit: Annotated[int,Query(ge=1,le=100)]=20,
                    offset: Annotated[int,Query(ge=0,le=1000000)]=0,
                    backup_id: Annotated[str | None,Query(max_length=36)]=None,
                    visibility_token: Annotated[str | None,Query(pattern=r'^[0-9a-f]{64}$')]=None):
        try:result=sql_query().details(sid(request),record_id,section=section,limit=limit,offset=offset,backup_id=backup_id,visibility_token=visibility_token)
        except ValueError:raise HTTPException(422) from None
        if not result['found']:raise HTTPException(404)
        return sql_result(result)

    @router.post('/api/v1/scans/inbound/validate')
    def validate_inbound(request: Request, command: InboundPreview):
        validator=InboundValidationService(service.gate,service.business_reader)
        try:
            return {'data':validator.validate(sid(request),command.box_codes,command.location_code,command.warehouse)}
        except ValueError:
            raise HTTPException(422) from None

    def submit(request, command, key, action):
        if len(request.headers.getlist('idempotency-key')) != 1:
            raise HTTPException(422)
        try:
            return {'data': service.submit(sid(request), key, action, command.fields)}
        except ValueError:
            raise HTTPException(422) from None

    Key = Annotated[str, Header(alias='Idempotency-Key', min_length=36, max_length=36)]

    @router.post('/api/v1/scans/inbound')
    def inbound(request: Request, command: InboundFields, key: Key):
        if command.target_warehouse is not None:
            if len(request.headers.getlist('idempotency-key')) != 1:
                raise HTTPException(422)
            try:
                return {'data': service.prepare_inbound(sid(request), key, command.target_warehouse, command.fields)}
            except ValueError:
                raise HTTPException(422) from None
        return submit(request, command, key, 'IN')

    @router.post('/api/v1/scans/outbound')
    def outbound(request: Request, command: ScanFields, key: Key):
        return submit(request, command, key, 'OUT')

    @router.post('/api/v1/scans/transfer')
    def transfer(request: Request, command: TransferFields, key: Key):
        if command.target_warehouse is not None:
            if len(request.headers.getlist('idempotency-key')) != 1:
                raise HTTPException(422)
            try:
                return {'data': service.prepare_transfer(sid(request), key, command.target_warehouse, command.fields)}
            except ValueError:
                raise HTTPException(422) from None
        return submit(request, command, key, 'MOVE')

    def tasks():
        worker = getattr(service, 'warehouse_tasks', None)
        if worker is None: raise HTTPException(503)
        return worker

    TaskId = Annotated[str, Path(pattern=r'^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')]

    @router.post('/api/v1/warehouse-tasks', status_code=202)
    def accept_task(request: Request, command: WarehouseTask, key: Key):
        if len(request.headers.getlist('idempotency-key')) != 1: raise HTTPException(422)
        try:
            result=tasks().submit(sid(request),key,command.action,command.target_warehouse,command.fields)
        except TaskQueueFull:
            return JSONResponse({'error':{'code':'TASK_QUEUE_FULL','message':'后台任务繁忙，请稍后使用原请求重试'}},status_code=503,headers={'Retry-After':'5'})
        except ValueError: raise HTTPException(422) from None
        return JSONResponse({'data':result},status_code=202,
            headers={'Location':f"/api/v1/warehouse-tasks/{result['task_id']}", 'Retry-After':'3'})

    @router.get('/api/v1/warehouse-tasks/{task_id}')
    def task_status(request: Request, task_id: TaskId):
        return {'data':tasks().status(sid(request),task_id)}

    @router.get('/api/v1/warehouse-tasks/{task_id}/review')
    def review_task(request: Request, task_id: TaskId):
        from finding_assistant.application.task_recovery import TaskRecovery
        return {'data': TaskRecovery(tasks()).inspect(sid(request), task_id)}

    @router.post('/api/v1/warehouse-tasks/{task_id}/continue-reviewed', status_code=202)
    def continue_reviewed_task(request: Request, task_id: TaskId, command: ReviewedTask):
        from finding_assistant.application.task_recovery import TaskRecovery
        try:
            result = TaskRecovery(tasks()).continue_original(sid(request), task_id, command.review_fingerprint)
        except TaskQueueFull:
            return JSONResponse({'error': {'code': 'TASK_QUEUE_FULL', 'message': '后台任务繁忙，请稍后重新核查原任务'}},
                                status_code=503, headers={'Retry-After': '5'})
        return {'data': result}

    @router.post('/api/v1/warehouse-tasks/{task_id}/resume', status_code=202)
    def resume_task(request: Request, task_id: TaskId):
        try: result=tasks().resume(sid(request),task_id)
        except TaskQueueFull:
            return JSONResponse({'error':{'code':'TASK_QUEUE_FULL','message':'后台任务繁忙，请稍后继续原任务'}},status_code=503,headers={'Retry-After':'5'})
        return JSONResponse({'data':result},status_code=202)

    def inventory():
        executor = getattr(service, 'inventory_execution', None)
        if executor is None:
            raise HTTPException(503)
        return executor

    RecordId = Annotated[str, Path(min_length=1, max_length=200, pattern=r'^[A-Za-z0-9]+$')]

    @router.post('/api/v1/inventory-executions/{record_id}/prepare')
    def prepare_inventory(request: Request, record_id: RecordId):
        return {'data': inventory().prepare(sid(request), record_id)}

    @router.post('/api/v1/inventory-executions/{record_id}/execute')
    def execute_inventory(request: Request, record_id: RecordId):
        return {'data': inventory().execute(sid(request), record_id)}

    @router.get('/api/v1/inventory-executions/{record_id}')
    def inventory_status(request: Request, record_id: RecordId):
        return {'data': inventory().status(sid(request), record_id)}

    def background():
        dispatcher = getattr(service, 'background_inventory', None)
        if dispatcher is None:
            raise HTTPException(503)
        return dispatcher

    @router.post('/api/v1/inventory-executions/{record_id}/dispatch', status_code=202)
    def dispatch_inventory(request: Request, record_id: RecordId):
        result = background().submit(sid(request), record_id)
        return JSONResponse({'data': result}, status_code=202,
            headers={'Location': f'/api/v1/inventory-executions/{record_id}/progress', 'Retry-After': '5'})

    @router.get('/api/v1/inventory-executions/{record_id}/progress')
    def inventory_progress(request: Request, record_id: RecordId):
        return {'data': background().progress(sid(request), record_id)}

    return router
