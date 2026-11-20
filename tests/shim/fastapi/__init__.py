"""Shim de TEST uniquement : sous-ensemble minimal de l'API FastAPI, construit sur Starlette.

Utilisé seulement si la vraie bibliothèque `fastapi` est absente (environnement de CI hors-ligne). Il couvre
exactement les usages du projet : routes GET/POST/PATCH, corps Pydantic, paramètres de chemin et de requête,
Request, HTTPException, middleware http, include_router et mount. En production, `pip install fastapi`.
"""
import inspect
import json
import typing

from pydantic import BaseModel, ValidationError
from starlette.applications import Starlette
from starlette.concurrency import run_in_threadpool
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.routing import Mount, Route

__all__ = ["FastAPI", "APIRouter", "HTTPException", "Request"]


class HTTPException(Exception):
    def __init__(self, status_code: int, detail=None):
        super().__init__(detail)
        self.status_code, self.detail = status_code, detail


def _default(o):
    if isinstance(o, BaseModel):
        return o.model_dump()
    if isinstance(o, (set, tuple)):
        return list(o)
    return str(o)


def _convert(value: str, ann):
    if ann is int:
        return int(value)
    if ann is float:
        return float(value)
    if ann is bool:
        return value.lower() in ("1", "true", "yes", "on")
    return value


def _endpoint(fn):
    sig = inspect.signature(fn)
    hints = typing.get_type_hints(fn)

    async def endpoint(request: Request):
        kwargs = {}
        try:
            for name, p in sig.parameters.items():
                ann = hints.get(name, p.annotation)
                if ann is Request:
                    kwargs[name] = request
                elif inspect.isclass(ann) and issubclass(ann, BaseModel):
                    raw = await request.body()
                    data = json.loads(raw) if raw else {}
                    kwargs[name] = ann.model_validate(data)
                elif name in request.path_params:
                    kwargs[name] = _convert(request.path_params[name], ann)
                else:
                    v = request.query_params.get(name)
                    if v is None:
                        if p.default is inspect.Parameter.empty:
                            return JSONResponse({"detail": f"missing {name}"}, 422)
                        kwargs[name] = p.default
                    else:
                        kwargs[name] = _convert(v, ann)
        except (ValidationError, ValueError) as exc:
            return JSONResponse({"detail": str(exc)}, 422)
        try:
            if inspect.iscoroutinefunction(fn):
                res = await fn(**kwargs)
            else:
                res = await run_in_threadpool(fn, **kwargs)
        except HTTPException as exc:
            return JSONResponse({"detail": exc.detail}, exc.status_code)
        if isinstance(res, Response):
            return res
        return Response(json.dumps(res, ensure_ascii=False, default=_default), media_type="application/json")
    return endpoint


class APIRouter:
    def __init__(self, prefix: str = ""):
        self.prefix, self.routes = prefix, []

    def _add(self, method, path):
        def deco(fn):
            self.routes.append((method, self.prefix + path, fn))
            return fn
        return deco

    def get(self, path):
        return self._add("GET", path)

    def post(self, path):
        return self._add("POST", path)

    def patch(self, path):
        return self._add("PATCH", path)


class FastAPI(Starlette):
    def __init__(self, title: str = "", **kw):
        super().__init__()
        self._api = APIRouter()

    def _register(self, method, path, fn):
        self.router.routes.append(Route(path, _endpoint(fn), methods=[method]))

    def get(self, path):
        def deco(fn):
            self._register("GET", path, fn)
            return fn
        return deco

    def post(self, path):
        def deco(fn):
            self._register("POST", path, fn)
            return fn
        return deco

    def include_router(self, r: APIRouter):
        for method, path, fn in r.routes:
            self._register(method, path, fn)

    def mount(self, path, app, name=None):
        self.router.routes.append(Mount(path, app=app, name=name))

    def middleware(self, kind):
        def deco(fn):
            self.add_middleware(BaseHTTPMiddleware, dispatch=fn)
            return fn
        return deco
