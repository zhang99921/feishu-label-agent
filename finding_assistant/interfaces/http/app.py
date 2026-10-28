# HTTP 接口层：只处理协议、参数、依赖注入和错误映射，业务状态变更委托给可信 backend。
# 调用链：路由 → 会话格式/请求键检查 → AuthenticatedWorkflow → 审计工作流 → 飞书存储。
# 默认 create_app() 没有装配业务后端；进程启动成功不代表真实飞书读写已经打通。
"""HTTP factory. With no trusted backend injected, inventory always stays closed.

Bearer values are opaque local server sessions, never user IDs, roles or Feishu
app tokens. The injected AuthenticatedWorkflow must verify them on every request.
"""
import inspect
import json
import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import Annotated,Callable

from fastapi import Depends,FastAPI,Header,HTTPException,Path,Query,Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.concurrency import run_in_threadpool

from finding_assistant.adapters.feishu.client import ProbeError
from finding_assistant.adapters.feishu.business_tables import BusinessDataUnavailable
from finding_assistant.infrastructure.business_sync import ReplicaUnavailable
from finding_assistant.security.sql_visibility import VisibilityUnavailable
from finding_assistant.application.service import GuardedWorkflow
from finding_assistant.application.workflow import Conflict
from finding_assistant.domain.quantity_rules import RuleError
from finding_assistant.domain.transfer import TransferRejected
from finding_assistant.domain.positions import PositionRejected
from finding_assistant.domain.inventory_posting import PostingStopped
from finding_assistant.security.errors import AccessDenied,AuthorizationUnavailable
from finding_assistant.security.errors import UpstreamThrottled
from finding_assistant.security.login import AuthenticationError, IdentityUnavailable
from finding_assistant.infrastructure.performance import request_trace
from finding_assistant.infrastructure.request_scope import request_scope
from .schemas import CorrectionMovement,DestinationMovement,InventoryQuery,Movement
from .schemas import PartialMovement,ReentryMovement,Text,UndoMovement

LOG = logging.getLogger("finding_assistant.http")


def validation_details(errors):
    """字段定位只保留接口声明名称；字典键、未知字段和自定义错误内容不回显。"""
    from .scan_routes import ScanFields, TransferFields, InboundFields, InboundPreview
    names = {'body', 'query', 'path', 'header', 'authorization', 'idempotency-key'}
    for model in (CorrectionMovement, DestinationMovement, InventoryQuery, Movement, PartialMovement,
                  ReentryMovement, UndoMovement, ScanFields, TransferFields, InboundFields, InboundPreview):
        names.update(model.model_fields)
    names.update({'行码', '来源区域', '目标区域', '目标托盘号', '原因', '事件类型'})
    names.update(f'箱号{i}' for i in range(1, 37))
    types = {'missing', 'extra_forbidden', 'string_type', 'string_too_short', 'string_too_long',
             'string_pattern_mismatch', 'int_type', 'int_parsing', 'greater_than', 'greater_than_equal',
             'less_than', 'less_than_equal', 'list_type', 'too_short', 'too_long', 'dict_type',
             'literal_error', 'value_error', 'bool_type', 'json_invalid', 'model_type', 'finite_number'}
    result = []
    for item in errors[:50]:
        parts = [str(part) if type(part) is int and 0 <= part <= 1000000 else
                 part if isinstance(part, str) and part in names else '[field]' for part in item.get('loc', ())[:8]]
        result.append({'path': '.'.join(parts), 'type': item.get('type') if item.get('type') in types else 'invalid_value'})
    return result


# 应用工厂。backend 必须由可信服务端装配；expose_docs 仅显式开启时提供接口文档。
def create_app(backend: GuardedWorkflow | None = None, *, expose_docs=False,on_shutdown: Callable | None = None,
               scan_service=None, scan_login=None, readiness_check: Callable | None = None,
               rejection_audit: Callable | None = None):
    if (scan_service is None) != (scan_login is None):
        raise ValueError('SCAN_SERVICE_AND_LOGIN_REQUIRED_TOGETHER')
    @asynccontextmanager
    async def lifespan(app):
        try:
            yield
        finally:
            if on_shutdown:
                result = on_shutdown()
                if inspect.isawaitable(result):
                    await result

    app = FastAPI(title="找货助手后端",version="2.0.0",debug=False,lifespan=lifespan,
        docs_url="/docs" if expose_docs else None,redoc_url=None,
        openapi_url="/openapi.json" if expose_docs else None)

    def failure(request,status,code,message,fields=None):
        error = {"code":code,"message":message,"request_id":getattr(request.state,"request_id",None)}
        if fields is not None:
            error["fields"] = fields
        headers = {"WWW-Authenticate":"Bearer"} if status == 401 else None
        return JSONResponse({"error":error},status_code=status,headers=headers)

    async def audited_failure(request, status, code, message, fields=None):
        response = failure(request, status, code, message, fields)
        if rejection_audit is not None and code in ('INVALID_REQUEST', 'BUSINESS_RULE_REJECTED', 'OPERATION_CONFLICT'):
            try:
                # 参数校验先于身份校验也可能失败；只传可信服务端编号和固定错误码。
                await run_in_threadpool(rejection_audit, request.state.request_id, code)
            except Exception:
                # 业务请求已经被拒绝，审计故障不能把它变为成功或诱发库存重试。
                response.headers['X-Audit-Status'] = 'unavailable'
                LOG.warning('request_id=%s audit_status=unavailable', request.state.request_id)
        return response

    # 生成服务端请求编号，统一响应头；日志只记录路由模板和耗时，不打印条码、凭据或请求体。
    @app.middleware("http")
    async def request_envelope(request,call_next):
        request.state.request_id = uuid.uuid4().hex
        started = time.monotonic()
        with request_scope(), request_trace() as timing:
            try:
                response = await call_next(request)
            except Exception:
                # No exception text, request URL/query/body, headers, tokens or stack trace.
                response = failure(request,500,"INTERNAL_ERROR","服务内部错误，请凭请求编号排查")
        response.headers["X-Request-ID"] = request.state.request_id
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers['Referrer-Policy'] = 'no-referrer'
        route = getattr(request.scope.get("route"),"path","unmatched")
        LOG.info("request_id=%s method=%s route=%s status=%s duration_ms=%.1f",
            request.state.request_id,request.method,route,response.status_code,(time.monotonic()-started)*1000)
        try:
            stages = timing.snapshot()
            if stages:
                LOG.info('performance=%s', json.dumps({'request_id': request.state.request_id, 'route': route,
                    'status': response.status_code, 'duration_ms': round((time.monotonic()-started)*1000, 3),
                    'stages': stages}, separators=(',', ':'), sort_keys=True))
        except Exception:
            pass  # 性能采样不影响已经确定的业务响应。
        return response

    # 参数错误只返回字段路径和错误类型，不把 Pydantic 中的原始输入回显给调用方。
    @app.exception_handler(UpstreamThrottled)
    async def throttled(request, error):
        response = failure(request,503,'UPSTREAM_THROTTLED','上游暂时限流，请稍后查询任务结果')
        response.headers['Retry-After'] = str(error.retry_after)
        return response

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request,error):
        fields = validation_details(error.errors())
        return await audited_failure(request,422,"INVALID_REQUEST","请求参数不符合接口要求",fields)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request,error):
        code,message = {401:("AUTHENTICATION_REQUIRED","请先登录"),
            403:("ACCESS_DENIED","当前请求无权执行此操作"),
            404:("NOT_FOUND","接口不存在"),
            405:("METHOD_NOT_ALLOWED","接口不支持该请求方法"),
            422:("INVALID_REQUEST","请求参数不符合接口要求"),
            503:("BACKEND_NOT_READY","业务后端尚未完成可信配置")}.get(error.status_code,("HTTP_ERROR","请求无法处理"))
        return await audited_failure(request,error.status_code,code,message)

    @app.exception_handler(TransferRejected)
    async def transfer_rejected(request, error):
        return failure(request, 409, 'TRANSFER_REJECTED', error.message,
                       {'reason_code': error.code, 'box_code': error.box_code})

    @app.exception_handler(PositionRejected)
    async def position_rejected(request, error):
        return failure(request, 409, 'POSITION_REJECTED', error.message,
                       {'reason_code': error.code, 'box_code': error.box_code})

    @app.exception_handler(PostingStopped)
    async def posting_stopped(request, error):
        return failure(request, 409, 'INVENTORY_RECONCILIATION_REQUIRED', '库存尚未确认完成，请按原因核实原任务',
                       {'reason_code': error.code, 'box_code': error.box_code,
                        **({'feedback': error.feedback} if hasattr(error, 'feedback') else {})})

    # 统一将领域异常映射为 HTTP 状态；503 待核实不能解释为“远端未写入”。
    mappings = (
        (AuthenticationError,401,"AUTHENTICATION_REQUIRED","登录已失效或未登录"),
        (IdentityUnavailable,503,"IDENTITY_UNAVAILABLE","飞书身份服务暂不可用，请稍后重试"),
        (BusinessDataUnavailable,503,"BUSINESS_VALIDATION_UNAVAILABLE","业务表数据或自动分配配置尚未完整核实，暂不能处理本次操作"),
        (ReplicaUnavailable,503,"SQL_REPLICA_NOT_READY","完整数据库副本尚未就绪，请检查同步状态"),
        (VisibilityUnavailable,503,"SQL_VISIBILITY_UNAVAILABLE","暂时无法完整核实当前账号的行列可见范围，请联系运维检查原生权限与同步状态"),
        (AuthorizationUnavailable,503,"AUTHORIZATION_UNAVAILABLE","暂时无法核实操作权限"),
        (AccessDenied,403,"ACCESS_DENIED","当前账号无权执行此操作"),
        (PermissionError,403,"ACCESS_DENIED","当前账号无权执行此操作"),
        (Conflict,409,"OPERATION_CONFLICT","数据或操作状态冲突，请刷新后确认"),
        (RuleError,422,"BUSINESS_RULE_REJECTED","请求不符合业务规则"),
        (ProbeError,503,"UPSTREAM_UNAVAILABLE","上游服务未确认结果，请保留原请求幂等键核实"),
    )
    def handler_for(status,code,message):
        async def handler(request,error):
            return await audited_failure(request,status,code,message)
        return handler
    for exception,status,code,message in mappings:
        app.add_exception_handler(exception,handler_for(status,code,message))

    # 这里只验证唯一 Bearer 头及格式；真实身份验证由 backend 执行，Bearer 不是飞书应用令牌。
    def session(request: Request,authorization: Annotated[str | None,Header()] = None):
        if len(request.headers.getlist("authorization")) != 1 or not authorization:
            raise HTTPException(401)
        scheme,separator,value = authorization.partition(" ")
        if scheme.lower() != "bearer" or not separator or not value or len(value) > 512 or any(c.isspace() for c in value):
            raise HTTPException(401)
        return value

    # 未注入可信业务实现时返回 503，避免误用无鉴权的测试流程。
    def ready_backend():
        if backend is None:
            raise HTTPException(503)
        return backend

    # 每次写请求必须带唯一且合法的 Idempotency-Key；网络重试必须沿用原键和原请求内容。
    def request_key(request: Request,value: Annotated[str,Header(alias="Idempotency-Key",min_length=1,max_length=100)]):
        if len(request.headers.getlist("idempotency-key")) != 1 or not value.strip() or any(ord(c)<32 or ord(c)==127 for c in value):
            raise HTTPException(422)
        return value

    Session = Annotated[str,Depends(session)]
    Backend = Annotated[GuardedWorkflow,Depends(ready_backend)]
    Key = Annotated[str,Depends(request_key)]

    # 只证明 HTTP 进程能响应，不检查飞书连接或业务权限。
    @app.get("/health/live")
    def liveness():
        return {"status":"alive"}

    # 装配后的扫码后端重新检查数据库；不将应用装配成功冒充上游飞书可用。
    @app.get("/health/ready")
    def readiness(request: Request):
        if backend is None and scan_service is None:
            return failure(request,503,"BACKEND_NOT_READY","业务后端尚未完成可信配置")
        if readiness_check is not None:
            try:
                readiness_check()
            except Exception:
                return failure(request,503,"DEPENDENCY_UNAVAILABLE","内部依赖暂不可用，请检查数据库连接及迁移")
        return {"status":"configured","upstream_health_verified":False,
                "database_verified":readiness_check is not None}

    @app.get("/api/v1/inventory/{unit}")
    def query_inventory(unit: Annotated[Text,Path()],query: Annotated[InventoryQuery,Query()],
                        sid: Session,service: Backend):
        return {"data":service.query(sid,unit,query.batch)}

    # 由路由固定 action；非目标仓操作统一传 location=None，用户不能在请求体中改动作。
    def submit(service,sid,key,model,action):
        payload = {**model.model_dump(),"action":action}
        payload.setdefault("location",None)
        return {"data":service.submit(sid,key,payload)}

    # 首次入库：未入区 → 在区；目标仓由 location 指定，托盘码由业务层分配。
    @app.post("/api/v1/movements/inbound")
    def inbound(command: DestinationMovement,sid: Session,service: Backend,key: Key):
        return submit(service,sid,key,command,"IN")

    # 整托出库：剩余箱数清零，仓库关联解除，原码进入冷却。
    @app.post("/api/v1/movements/outbound")
    def outbound(command: Movement,sid: Session,service: Backend,key: Key):
        return submit(service,sid,key,command,"OUT")

    # 转仓：从当前仓流转到目标仓；旧码冷却，并分配目标仓的新码。
    @app.post("/api/v1/movements/transfer")
    def transfer(command: DestinationMovement,sid: Session,service: Backend,key: Key):
        return submit(service,sid,key,command,"MOVE")

    # 按整箱扣减；仍有箱子时保留仓库和托盘码，减至零时按出库处理。
    @app.post("/api/v1/movements/partial-outbound")
    def partial_outbound(command: PartialMovement,sid: Session,service: Backend,key: Key):
        return submit(service,sid,key,command,"PARTIAL_OUT")

    # 已出库托盘显式重新入库；必须确认新的实物箱数，不能把旧请求重试当成重新入库。
    @app.post("/api/v1/movements/reentry")
    def reentry(command: ReentryMovement,sid: Session,service: Backend,key: Key):
        return submit(service,sid,key,command,"REENTER")

    # 管理员纠正箱数；必须关联已完成流水、说明原因并确认实物。
    @app.post("/api/v1/administration/corrections")
    def correct(command: CorrectionMovement,sid: Session,service: Backend,key: Key):
        return submit(service,sid,key,command,"CORRECT")

    # 管理员补偿撤销；存在后续流转时拒绝简单回滚，防止覆盖后续操作。
    @app.post("/api/v1/administration/undo")
    def undo(command: UndoMovement,sid: Session,service: Backend,key: Key):
        return submit(service,sid,key,command,"UNDO")

    if scan_service is not None:
        from .scan_routes import scan_router
        app.include_router(scan_router(scan_service, scan_login))
    from .mobile import mobile_router
    app.include_router(mobile_router(scan_service))
    return app
