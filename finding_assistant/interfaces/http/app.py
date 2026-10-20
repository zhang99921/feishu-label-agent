"""HTTP factory. With no trusted backend injected, inventory always stays closed.

Bearer values are opaque local server sessions, never user IDs, roles or Feishu
app tokens. The injected AuthenticatedWorkflow must verify them on every request.
"""
import inspect
import logging
import time
import uuid
from contextlib import asynccontextmanager
from typing import Annotated,Callable

from fastapi import Depends,FastAPI,Header,HTTPException,Path,Query,Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from finding_assistant.adapters.feishu.client import ProbeError
from finding_assistant.application.service import GuardedWorkflow
from finding_assistant.application.workflow import Conflict
from finding_assistant.domain.quantity_rules import RuleError
from finding_assistant.security.errors import AccessDenied,AuthorizationUnavailable
from finding_assistant.security.login import AuthenticationError
from .schemas import CorrectionMovement,DestinationMovement,InventoryQuery,Movement
from .schemas import PartialMovement,ReentryMovement,Text,UndoMovement

LOG = logging.getLogger("finding_assistant.http")


def create_app(backend: GuardedWorkflow | None = None, *, expose_docs=False,on_shutdown: Callable | None = None):
    @asynccontextmanager
    async def lifespan(app):
        try:
            yield
        finally:
            if on_shutdown:
                result = on_shutdown()
                if inspect.isawaitable(result):
                    await result

    app = FastAPI(title="找货助手后端",version="1.0.0",debug=False,lifespan=lifespan,
        docs_url="/docs" if expose_docs else None,redoc_url=None,
        openapi_url="/openapi.json" if expose_docs else None)

    def failure(request,status,code,message,fields=None):
        error = {"code":code,"message":message,"request_id":getattr(request.state,"request_id",None)}
        if fields is not None:
            error["fields"] = fields
        headers = {"WWW-Authenticate":"Bearer"} if status == 401 else None
        return JSONResponse({"error":error},status_code=status,headers=headers)

    @app.middleware("http")
    async def request_envelope(request,call_next):
        request.state.request_id = uuid.uuid4().hex
        started = time.monotonic()
        try:
            response = await call_next(request)
        except Exception:
            # No exception text, request URL/query/body, headers, tokens or stack trace.
            response = failure(request,500,"INTERNAL_ERROR","服务内部错误，请凭请求编号排查")
        response.headers["X-Request-ID"] = request.state.request_id
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        route = getattr(request.scope.get("route"),"path","unmatched")
        LOG.info("request_id=%s method=%s route=%s status=%s duration_ms=%.1f",
            request.state.request_id,request.method,route,response.status_code,(time.monotonic()-started)*1000)
        return response

    @app.exception_handler(RequestValidationError)
    async def invalid_request(request,error):
        fields = [{"path":".".join(str(v) for v in item["loc"]),"type":item["type"]} for item in error.errors()]
        return failure(request,422,"INVALID_REQUEST","请求参数不符合接口要求",fields)

    @app.exception_handler(StarletteHTTPException)
    async def http_error(request,error):
        code,message = {401:("AUTHENTICATION_REQUIRED","请先登录"),
            404:("NOT_FOUND","接口不存在"),
            405:("METHOD_NOT_ALLOWED","接口不支持该请求方法"),
            422:("INVALID_REQUEST","请求参数不符合接口要求"),
            503:("BACKEND_NOT_READY","业务后端尚未完成可信配置")}.get(error.status_code,("HTTP_ERROR","请求无法处理"))
        return failure(request,error.status_code,code,message)

    mappings = (
        (AuthenticationError,401,"AUTHENTICATION_REQUIRED","登录已失效或未登录"),
        (AuthorizationUnavailable,503,"AUTHORIZATION_UNAVAILABLE","暂时无法核实操作权限"),
        (AccessDenied,403,"ACCESS_DENIED","当前账号无权执行此操作"),
        (PermissionError,403,"ACCESS_DENIED","当前账号无权执行此操作"),
        (Conflict,409,"OPERATION_CONFLICT","数据或操作状态冲突，请刷新后确认"),
        (RuleError,422,"BUSINESS_RULE_REJECTED","请求不符合业务规则"),
        (ProbeError,503,"UPSTREAM_UNAVAILABLE","上游服务未确认结果，请保留原请求幂等键核实"),
    )
    def handler_for(status,code,message):
        async def handler(request,error):
            return failure(request,status,code,message)
        return handler
    for exception,status,code,message in mappings:
        app.add_exception_handler(exception,handler_for(status,code,message))

    def session(request: Request,authorization: Annotated[str | None,Header()] = None):
        if len(request.headers.getlist("authorization")) != 1 or not authorization:
            raise HTTPException(401)
        scheme,separator,value = authorization.partition(" ")
        if scheme.lower() != "bearer" or not separator or not value or len(value) > 512 or any(c.isspace() for c in value):
            raise HTTPException(401)
        return value

    def ready_backend():
        if backend is None:
            raise HTTPException(503)
        return backend

    def request_key(request: Request,value: Annotated[str,Header(alias="Idempotency-Key",min_length=1,max_length=100)]):
        if len(request.headers.getlist("idempotency-key")) != 1 or not value.strip() or any(ord(c)<32 or ord(c)==127 for c in value):
            raise HTTPException(422)
        return value

    Session = Annotated[str,Depends(session)]
    Backend = Annotated[GuardedWorkflow,Depends(ready_backend)]
    Key = Annotated[str,Depends(request_key)]

    @app.get("/health/live")
    def liveness():
        return {"status":"alive"}

    @app.get("/health/ready")
    def readiness(request: Request):
        if backend is None:
            return failure(request,503,"BACKEND_NOT_READY","业务后端尚未完成可信配置")
        return {"status":"configured","upstream_health_verified":False}

    @app.get("/api/v1/inventory/{unit}")
    def query_inventory(unit: Annotated[Text,Path()],query: Annotated[InventoryQuery,Query()],
                        sid: Session,service: Backend):
        return {"data":service.query(sid,unit,query.batch)}

    def submit(service,sid,key,model,action):
        payload = {**model.model_dump(),"action":action}
        payload.setdefault("location",None)
        return {"data":service.submit(sid,key,payload)}

    @app.post("/api/v1/movements/inbound")
    def inbound(command: DestinationMovement,sid: Session,service: Backend,key: Key):
        return submit(service,sid,key,command,"IN")

    @app.post("/api/v1/movements/outbound")
    def outbound(command: Movement,sid: Session,service: Backend,key: Key):
        return submit(service,sid,key,command,"OUT")

    @app.post("/api/v1/movements/transfer")
    def transfer(command: DestinationMovement,sid: Session,service: Backend,key: Key):
        return submit(service,sid,key,command,"MOVE")

    @app.post("/api/v1/movements/partial-outbound")
    def partial_outbound(command: PartialMovement,sid: Session,service: Backend,key: Key):
        return submit(service,sid,key,command,"PARTIAL_OUT")

    @app.post("/api/v1/movements/reentry")
    def reentry(command: ReentryMovement,sid: Session,service: Backend,key: Key):
        return submit(service,sid,key,command,"REENTER")

    @app.post("/api/v1/administration/corrections")
    def correct(command: CorrectionMovement,sid: Session,service: Backend,key: Key):
        return submit(service,sid,key,command,"CORRECT")

    @app.post("/api/v1/administration/undo")
    def undo(command: UndoMovement,sid: Session,service: Backend,key: Key):
        return submit(service,sid,key,command,"UNDO")

    return app
