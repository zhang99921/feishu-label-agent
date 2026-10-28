"""手机操作页面及固定资源；业务读写仍通过原有鉴权接口。"""
from pathlib import Path

from fastapi import APIRouter
from fastapi.responses import FileResponse, JSONResponse


ASSETS = Path(__file__).with_name('mobile_assets')
FILES = {'app.js': 'text/javascript', 'model.mjs': 'text/javascript',
         'location-card.mjs': 'text/javascript', 'scanner.mjs': 'text/javascript', 'style.css': 'text/css'}


def mobile_router(service=None):
    router = APIRouter()
    headers = {'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
               'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; "
                   "connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; form-action 'self'"}

    @router.get('/app', include_in_schema=False)
    def page():
        return FileResponse(ASSETS / 'index.html', media_type='text/html', headers=headers)

    @router.get('/app/assets/{name}', include_in_schema=False)
    def asset(name: str):
        # 固定白名单，不将任意URL路径映射到磁盘。
        if name not in FILES:
            return JSONResponse({'error': {'message': '资源不存在'}}, status_code=404, headers=headers)
        return FileResponse(ASSETS / name, media_type=FILES[name], headers=headers)

    @router.get('/app/config', include_in_schema=False)
    def config():
        return JSONResponse({'warehouses': ['优福斯仓', '欣源仓'], 'max_boxes': 36,
            'inventory_enabled': bool(service and getattr(service, 'background_inventory', None)),
            'query_enabled': bool(service and getattr(service, 'sql_query', None)),
            'images_enabled': False, 'labels_enabled': False}, headers=headers)

    return router
