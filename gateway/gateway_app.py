
# import os
# import json
# import time
# import traceback
# from typing import Optional, Tuple, List

# import grpc
# from grpc import StatusCode
# from fastapi import FastAPI, Request, HTTPException, Depends, Query
# from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
# from pydantic import BaseModel
# from fastapi.responses import JSONResponse

# # Primary auth (auth_access) proto modules (used for /auth/*)
# import auth_access_pb2 as auth_access_pb
# import auth_access_pb2_grpc as auth_access_pb_grpc

# import auth_pb2 as legacy_auth_pb, auth_pb2_grpc as legacy_auth_pb_grpc



# # Search proto (optional - for SaveHistory/ListHistory/DeleteHistory)
# import search_pb2 as search_pb
# import search_pb2_grpc as search_pb_grpc

# # MCP client (optional)
# from mcp.client.streamable_http import streamablehttp_client
# from mcp.client.session import ClientSession

# # Redis async client
# import redis.asyncio as redis

# # ----------------- Config -----------------
# AUTH_SERVICE_ADDR = os.environ.get("AUTH_SERVICE_ADDR", "localhost:50054")   # primary auth for /auth endpoints
# LEGACY_AUTH_ADDR = os.environ.get("LEGACY_AUTH_ADDR", "localhost:50051")   # your pasted auth server (for /search)
# SEARCH_SERVICE_ADDR = os.environ.get("SEARCH_SERVICE_ADDR", "localhost:50055")
# MCP_URL = os.environ.get("MCP_URL", "https://server.smithery.ai/@nickclyde/duckduckgo-mcp-server/mcp")
# API_KEY = os.environ.get("MCP_API_KEY", "775e8343-7c8c-47b0-8d12-93f9b45c293c")
# PROFILE = os.environ.get("MCP_PROFILE", "developing-marten-gJ1abJ")
# REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
# REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
# AUTH_CACHE_TTL = int(os.environ.get("AUTH_CACHE_TTL", 3600))

# # ----------------- App -----------------
# app = FastAPI(title="Unified Gateway (primary auth + legacy-search-auth)")
# redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
# security = HTTPBearer()

# # ----------------- Pydantic models -----------------
# class RegisterIn(BaseModel):
#     email: str
#     password: str

# class LoginIn(BaseModel):
#     email: str
#     password: str

# class RefreshIn(BaseModel):
#     refresh_token: str

# class TokenOut(BaseModel):
#     access_token: str
#     refresh_token: str

# class ValidateIn(BaseModel):
#     token: str

# class ValidateOut(BaseModel):
#     valid: bool
#     user_id: Optional[str]
#     role: Optional[str]
#     expires_at: Optional[int]
#     error: Optional[str]

# class HistoryItemOut(BaseModel):
#     id: int
#     user_id: str
#     query: str
#     results: List[dict]
#     timestamp: str

# # ----------------- startup / shutdown -----------------
# @app.on_event("startup")
# async def startup():
#     # primary auth_access stub (for /auth endpoints)
#     app.state.auth_channel = grpc.aio.insecure_channel(AUTH_SERVICE_ADDR)
#     app.state.auth_stub = auth_access_pb_grpc.AuthServiceStub(app.state.auth_channel)

#     # legacy auth stub (for /search login/verify)
#     app.state.legacy_auth_channel = grpc.aio.insecure_channel(LEGACY_AUTH_ADDR)
#     app.state.legacy_auth_stub = legacy_auth_pb_grpc.AuthServiceStub(app.state.legacy_auth_channel)

#     # search service stub (optional)
#     app.state.search_channel = grpc.aio.insecure_channel(SEARCH_SERVICE_ADDR)
#     app.state.search_stub = search_pb_grpc.GatewayAuthSearchStub(app.state.search_channel)

# @app.on_event("shutdown")
# async def shutdown():
#     if hasattr(app.state, "auth_channel"):
#         await app.state.auth_channel.close()
#     if hasattr(app.state, "legacy_auth_channel"):
#         await app.state.legacy_auth_channel.close()
#     if hasattr(app.state, "search_channel"):
#         await app.state.search_channel.close()

# # ----------------- helpers -----------------
# def grpc_error_to_http(e: grpc.aio.AioRpcError) -> HTTPException:
#     code = e.code()
#     details = e.details() or ""
#     if code == StatusCode.NOT_FOUND:
#         return HTTPException(status_code=404, detail=details)
#     if code == StatusCode.INVALID_ARGUMENT:
#         return HTTPException(status_code=400, detail=details)
#     if code == StatusCode.UNAUTHENTICATED:
#         return HTTPException(status_code=401, detail=details)
#     if code == StatusCode.PERMISSION_DENIED:
#         return HTTPException(status_code=403, detail=details)
#     if code == StatusCode.ALREADY_EXISTS:
#         return HTTPException(status_code=409, detail=details)
#     if code == StatusCode.DEADLINE_EXCEEDED:
#         return HTTPException(status_code=504, detail="Upstream timeout")
#     if code == StatusCode.UNAVAILABLE:
#         return HTTPException(status_code=503, detail="Upstream unavailable")
#     return HTTPException(status_code=500, detail=f"Upstream gRPC error: {details}")

# def metadata_from_request(req: Request) -> Tuple[Tuple[str, str], ...]:
#     meta = []
#     auth = req.headers.get("authorization")
#     if auth:
#         meta.append(("authorization", auth))
#     return tuple(meta)

# # Validate token using primary auth_access.ValidateToken (returns valid + expires)
# async def validate_token_with_primary(token: str):
#     cached = await redis_client.get(f"token:{token}")
#     if cached:
#         return json.loads(cached)

#     stub = app.state.auth_stub  # auth_access stub
#     req = auth_access_pb.ValidateTokenRequest(token=token)
#     try:
#         resp = await stub.ValidateToken(req, timeout=4.0)
#     except grpc.aio.AioRpcError as e:
#         raise grpc_error_to_http(e)

#     if not getattr(resp, "valid", False):
#         raise HTTPException(status_code=401, detail=getattr(resp, "error", "Invalid token"))

#     payload = {"sub": getattr(resp, "user_id", ""), "role": getattr(resp, "role", "")}
#     expires_at = getattr(resp, "expires_at", 0) or 0
#     try:
#         expires_at = int(expires_at)
#     except Exception:
#         expires_at = 0

#     if expires_at and expires_at > int(time.time()):
#         ttl = expires_at - int(time.time())
#         await redis_client.setex(f"token:{token}", ttl, json.dumps(payload))
#     else:
#         await redis_client.setex(f"token:{token}", AUTH_CACHE_TTL, json.dumps(payload))

#     return payload

# # Verify token using legacy auth Verify (no exp returned)
# async def verify_and_cache_using_legacy(token: str):
#     cached = await redis_client.get(f"token:{token}")
#     if cached:
#         return json.loads(cached)

#     stub = app.state.legacy_auth_stub
#     req = legacy_auth_pb.VerifyRequest(token=token)
#     try:
#         resp = await stub.Verify(req, timeout=4.0)
#     except grpc.aio.AioRpcError as e:
#         raise grpc_error_to_http(e)

#     # legacy Verify returns sub & role on success
#     payload = {"sub": getattr(resp, "sub", ""), "role": getattr(resp, "role", "")}
#     await redis_client.setex(f"token:{token}", AUTH_CACHE_TTL, json.dumps(payload))
#     return payload

# # dynamic dependency: if request.path startswith /search use legacy auth; else use primary auth
# async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), request: Request = None):
#     token = credentials.credentials
#     if not token:
#         raise HTTPException(status_code=401, detail="Authorization token missing")
#     path = request.scope.get("path", "") if request is not None else ""
#     # use legacy auth for search routes
#     if path.startswith("/search"):
#         return await verify_and_cache_using_legacy(token)
#     # otherwise use primary auth service
#     return await validate_token_with_primary(token)

# # ----------------- Auth endpoints (HTTP -> primary auth_access gRPC) -----------------
# @app.post("/auth/register", response_model=TokenOut)
# async def register(payload: RegisterIn, request: Request):
#     stub = app.state.auth_stub
#     req = auth_access_pb.RegisterRequest(email=payload.email, password=payload.password)
#     try:
#         resp = await stub.Register(req, timeout=5.0, metadata=metadata_from_request(request))
#         return TokenOut(access_token=resp.access_token, refresh_token=resp.refresh_token)
#     except grpc.aio.AioRpcError as e:
#         raise grpc_error_to_http(e)

# @app.post("/auth/login", response_model=TokenOut)
# async def auth_login(payload: LoginIn, request: Request):
#     stub = app.state.auth_stub
#     req = auth_access_pb.LoginRequest(email=payload.email, password=payload.password)
#     try:
#         resp = await stub.Login(req, timeout=5.0, metadata=metadata_from_request(request))
#         return TokenOut(access_token=resp.access_token, refresh_token=resp.refresh_token)
#     except grpc.aio.AioRpcError as e:
#         raise grpc_error_to_http(e)

# @app.post("/auth/refresh", response_model=TokenOut)
# async def refresh(payload: RefreshIn, request: Request):
#     stub = app.state.auth_stub
#     req = auth_access_pb.RefreshRequest(refresh_token=payload.refresh_token)
#     try:
#         resp = await stub.Refresh(req, timeout=5.0, metadata=metadata_from_request(request))
#         return TokenOut(access_token=resp.access_token, refresh_token=resp.refresh_token)
#     except grpc.aio.AioRpcError as e:
#         raise grpc_error_to_http(e)

# @app.post("/auth/validate", response_model=ValidateOut)
# async def validate(payload: ValidateIn, request: Request):
#     stub = app.state.auth_stub
#     req = auth_access_pb.ValidateTokenRequest(token=payload.token)
#     try:
#         resp = await stub.ValidateToken(req, timeout=4.0, metadata=metadata_from_request(request))
#         return ValidateOut(
#             valid=resp.valid,
#             user_id=resp.user_id or None,
#             role=resp.role or None,
#             expires_at=resp.expires_at or None,
#             error=resp.error or None,
#         )
#     except grpc.aio.AioRpcError as e:
#         raise grpc_error_to_http(e)

# # ----------------- Search endpoints (use legacy auth for login/verify and for protection) -----------------
# @app.post("/search/login", response_model=TokenOut)
# async def search_login(payload: LoginIn, request: Request):
#     """
#     Use legacy auth server (LEGACY_AUTH_ADDR) Login RPC for search-specific login.
#     """
#     stub = app.state.legacy_auth_stub
#     req = legacy_auth_pb.LoginRequest(email=payload.email, password=payload.password)
#     try:
#         resp = await stub.Login(req, timeout=5.0, metadata=metadata_from_request(request))
#         # optional: cache returned access token via legacy Verify
#         try:
#             await verify_and_cache_using_legacy(resp.access_token)
#         except Exception:
#             pass
#         return TokenOut(access_token=resp.access_token, refresh_token=resp.refresh_token)
#     except grpc.aio.AioRpcError as e:
#         raise grpc_error_to_http(e)

# @app.post("/search/verify", response_model=ValidateOut)
# async def search_verify(payload: ValidateIn, request: Request):
#     """
#     Verify using legacy Verify RPC and map to ValidateOut.
#     """
#     stub = app.state.legacy_auth_stub
#     req = legacy_auth_pb.VerifyRequest(token=payload.token)
#     try:
#         resp = await stub.Verify(req, timeout=4.0, metadata=metadata_from_request(request))
#         return ValidateOut(valid=True, user_id=resp.sub or None, role=resp.role or None, expires_at=None, error=None)
#     except grpc.aio.AioRpcError as e:
#         if e.code() == grpc.StatusCode.UNAUTHENTICATED:
#             return ValidateOut(valid=False, user_id=None, role=None, expires_at=None, error=e.details())
#         raise grpc_error_to_http(e)

# # protected search: perform search, save history to search service
# @app.post("/search/", dependencies=[Depends(get_current_user)])
# async def perform_search(query: str = Query(..., description="Search query"), current_user = Depends(get_current_user)):
#     user_id = str(int(current_user.get("sub"))) if current_user.get("sub") else ""
#     cache_key = f"search:{user_id}:{query.lower().strip()}"
#     cached = await redis_client.get(cache_key)
#     if cached:
#         return JSONResponse(content=json.loads(cached))

#     try:
#         url = f"{MCP_URL}?api_key={API_KEY}&profile={PROFILE}"
#         async with streamablehttp_client(url) as (read_stream, write_stream, _):
#             async with ClientSession(read_stream, write_stream) as sess:
#                 await sess.initialize()
#                 tools = await sess.list_tools()
#                 tool_to_use = "search" if "search" in [t.name for t in tools.tools] else tools.tools[0].name
#                 res = await sess.call_tool(tool_to_use, {"query": query})
#                 outputs = res.dict().get("content", [])
#                 results = [item.get("text") for item in outputs if "text" in item]

#         # Save history via Search gRPC (best-effort)
#         try:
#             stub = app.state.search_stub
#             pb_results = [search_pb.SearchResult(text=(t or ""), url="") for t in results]
#             save_req = search_pb.SaveHistoryRequest(user_id=user_id, query=query, results=pb_results)
#             await stub.SaveHistory(save_req, timeout=5.0)
#         except grpc.aio.AioRpcError as e:
#             print("⚠️ SaveHistory RPC failed:", e)
#         except Exception as e:
#             print("⚠️ SaveHistory (client) error:", e)

#         data = {"query": query, "results": results, "user_id": user_id}
#         await redis_client.setex(cache_key, 3600, json.dumps(data))
#         return JSONResponse(content=data)

#     except Exception as e:
#         print("⚠️ MCP ERROR TRACE:", traceback.format_exc())
#         raise HTTPException(status_code=500, detail=f"Search MCP error: {str(e)}")

# @app.get("/search/history", response_model=List[HistoryItemOut], dependencies=[Depends(get_current_user)])
# async def list_user_searches(limit: int = Query(50), offset: int = Query(0), current_user = Depends(get_current_user)):
#     user_id = str(int(current_user.get("sub")))
#     stub = app.state.search_stub
#     req = search_pb.ListHistoryRequest(user_id=user_id, limit=limit, offset=offset)
#     try:
#         resp = await stub.ListHistory(req, timeout=5.0)
#     except grpc.aio.AioRpcError as e:
#         raise grpc_error_to_http(e)

#     out = []
#     for it in resp.items:
#         results = [{"text": r.text, "url": getattr(r, "url", "")} for r in it.results]
#         out.append(HistoryItemOut(
#             id=int(it.id),
#             user_id=str(it.user_id),
#             query=str(it.query),
#             results=results,
#             timestamp=str(it.timestamp),
#         ))
#     return out

# @app.delete("/search/{item_id}", dependencies=[Depends(get_current_user)])
# async def delete_search_item(item_id: int, current_user = Depends(get_current_user)):
#     user_id = str(int(current_user.get("sub")))
#     stub = app.state.search_stub
#     req = search_pb.DeleteHistoryRequest(id=item_id, user_id=user_id)
#     try:
#         resp = await stub.DeleteHistory(req, timeout=5.0)
#     except grpc.aio.AioRpcError as e:
#         raise grpc_error_to_http(e)

#     if not getattr(resp, "ok", False):
#         raise HTTPException(status_code=400, detail=getattr(resp, "error", "delete failed"))
#     return {"message": f"Search history item {item_id} deleted successfully"}

# # root
# @app.get("/")
# def root():
#     return {
#         "status": "unified gateway",
#         "primary_auth": AUTH_SERVICE_ADDR,
#         "legacy_auth": LEGACY_AUTH_ADDR,
#         "search_grpc": SEARCH_SERVICE_ADDR
#     }


# gateway_app.py
# gateway_app.py

# gateway_app.py

# import os
# import json
# import time
# from typing import Optional, Tuple

# import grpc
# from grpc import StatusCode
# from fastapi import FastAPI, Request, Depends, HTTPException, Query
# from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
# from pydantic import BaseModel
# import redis.asyncio as redis

# # ----------------- gRPC stubs -----------------
# # Primary auth
# import auth_access_pb2 as auth_access_pb
# import auth_access_pb2_grpc as auth_access_pb_grpc

# # Legacy auth (for verification only if needed)
# import auth_pb2 as legacy_auth_pb
# import auth_pb2_grpc as legacy_auth_pb_grpc

# # Image service
# import image_pb2, image_pb2_grpc

# # ----------------- Config -----------------
# AUTH_SERVICE_ADDR = os.environ.get("AUTH_SERVICE_ADDR", "localhost:50054")
# LEGACY_AUTH_ADDR = os.environ.get("LEGACY_AUTH_ADDR", "localhost:50051")
# IMAGE_ADDR = os.environ.get("IMAGE_SERVICE_ADDR", "localhost:50057")

# REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
# REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
# AUTH_CACHE_TTL = int(os.environ.get("AUTH_CACHE_TTL", 3600))

# # ----------------- App -----------------
# app = FastAPI(title="Unified Gateway (auth + image)")
# redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
# security = HTTPBearer()

# # ----------------- Pydantic models -----------------
# class RegisterIn(BaseModel):
#     email: str
#     password: str

# class LoginIn(BaseModel):
#     email: str
#     password: str

# class RefreshIn(BaseModel):
#     refresh_token: str

# class TokenOut(BaseModel):
#     access_token: str
#     refresh_token: str

# class ValidateIn(BaseModel):
#     token: str

# class ValidateOut(BaseModel):
#     valid: bool
#     user_id: Optional[str]
#     role: Optional[str]
#     expires_at: Optional[int]
#     error: Optional[str]

# # ----------------- Startup / Shutdown -----------------
# @app.on_event("startup")
# async def startup():
#     app.state.auth_channel = grpc.aio.insecure_channel(AUTH_SERVICE_ADDR)
#     app.state.auth_stub = auth_access_pb_grpc.AuthServiceStub(app.state.auth_channel)

# @app.on_event("shutdown")
# async def shutdown():
#     if hasattr(app.state, "auth_channel"):
#         await app.state.auth_channel.close()

# # ----------------- Helpers -----------------
# def grpc_error_to_http(e: grpc.aio.AioRpcError) -> HTTPException:
#     code, details = e.code(), e.details() or ""
#     mapping = {
#         StatusCode.NOT_FOUND: 404,
#         StatusCode.INVALID_ARGUMENT: 400,
#         StatusCode.UNAUTHENTICATED: 401,
#         StatusCode.PERMISSION_DENIED: 403,
#         StatusCode.ALREADY_EXISTS: 409,
#         StatusCode.DEADLINE_EXCEEDED: 504,
#         StatusCode.UNAVAILABLE: 503,
#     }
#     if code in mapping:
#         return HTTPException(status_code=mapping[code], detail=details or str(code))
#     return HTTPException(status_code=500, detail=f"gRPC error: {details}")

# def metadata_from_request(req: Request) -> Tuple[Tuple[str, str], ...]:
#     auth = req.headers.get("authorization")
#     return (("authorization", auth),) if auth else ()

# async def validate_token(token: str):
#     cached = await redis_client.get(f"token:{token}")
#     if cached:
#         return json.loads(cached)
#     stub = app.state.auth_stub
#     resp = await stub.ValidateToken(auth_access_pb.ValidateTokenRequest(token=token), timeout=4.0)
#     if not resp.valid:
#         raise HTTPException(status_code=401, detail=resp.error or "Invalid token")
#     payload = {"sub": resp.user_id, "role": resp.role}
#     ttl = max(int(resp.expires_at or 0) - int(time.time()), AUTH_CACHE_TTL)
#     await redis_client.setex(f"token:{token}", ttl, json.dumps(payload))
#     return payload

# async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
#     token = credentials.credentials
#     return await validate_token(token)

# # ----------------- Auth Endpoints -----------------
# @app.post("/auth/register", response_model=TokenOut)
# async def register(payload: RegisterIn, request: Request):
#     resp = await app.state.auth_stub.Register(
#         auth_access_pb.RegisterRequest(email=payload.email, password=payload.password),
#         timeout=5.0,
#         metadata=metadata_from_request(request),
#     )
#     return TokenOut(access_token=resp.access_token, refresh_token=resp.refresh_token)

# @app.post("/auth/login", response_model=TokenOut)
# async def auth_login(payload: LoginIn, request: Request):
#     resp = await app.state.auth_stub.Login(
#         auth_access_pb.LoginRequest(email=payload.email, password=payload.password),
#         timeout=5.0,
#         metadata=metadata_from_request(request),
#     )
#     return TokenOut(access_token=resp.access_token, refresh_token=resp.refresh_token)

# @app.post("/auth/refresh", response_model=TokenOut)
# async def refresh(payload: RefreshIn, request: Request):
#     resp = await app.state.auth_stub.Refresh(
#         auth_access_pb.RefreshRequest(refresh_token=payload.refresh_token),
#         timeout=5.0,
#         metadata=metadata_from_request(request),
#     )
#     return TokenOut(access_token=resp.access_token, refresh_token=resp.refresh_token)

# @app.post("/auth/validate", response_model=ValidateOut)
# async def validate(payload: ValidateIn, request: Request):
#     resp = await app.state.auth_stub.ValidateToken(
#         auth_access_pb.ValidateTokenRequest(token=payload.token),
#         timeout=4.0,
#         metadata=metadata_from_request(request),
#     )
#     return ValidateOut(
#         valid=resp.valid,
#         user_id=resp.user_id or None,
#         role=resp.role or None,
#         expires_at=resp.expires_at or None,
#         error=resp.error or None,
#     )

# # ----------------- Image Endpoints -----------------
# async def grpc_verify(token: str):
#     async with grpc.aio.insecure_channel(LEGACY_AUTH_ADDR) as ch:
#         stub = legacy_auth_pb_grpc.AuthServiceStub(ch)
#         try:
#             resp = await stub.Verify(legacy_auth_pb.VerifyRequest(token=token), timeout=5)
#             return {"sub": resp.sub, "role": getattr(resp, "role", "")}
#         except grpc.aio.AioRpcError as e:
#             raise HTTPException(status_code=401, detail=f"Token invalid: {e.details()}")

# async def get_current_user_for_image(credentials: HTTPAuthorizationCredentials = Depends(security)):
#     token = credentials.credentials
#     payload = await grpc_verify(token)
#     return payload, token

# @app.post("/image/generate")
# async def generate_image(
#     prompt: str = Query(..., description="Prompt for image generation"),
#     user_info=Depends(get_current_user_for_image),
# ):
#     user_payload, token = user_info
#     async with grpc.aio.insecure_channel(IMAGE_ADDR) as ch:
#         stub = image_pb2_grpc.ImageServiceStub(ch)
#         req = image_pb2.GenerateImageRequest(
#             user_id=user_payload["sub"],
#             prompt=prompt,
#             model="flux",
#             profile="mixed-viper-NggMmT",
#         )
#         metadata = (("authorization", f"Bearer {token}"),)
#         try:
#             resp = await stub.GenerateImage(req, metadata=metadata, timeout=120)
#             return {
#                 "ok": resp.ok,
#                 "message": resp.message,
#                 "image_url": resp.image_url,
#                 "results": json.loads(resp.results_json) if resp.results_json else None,
#                 "id": resp.id,
#                 "timestamp": resp.timestamp,
#             }
#         except grpc.aio.AioRpcError as e:
#             raise HTTPException(status_code=502, detail=f"ImageService error: {e.details()}")

# @app.get("/image/history")
# async def list_history(user_info=Depends(get_current_user_for_image)):
#     user_payload, token = user_info
#     async with grpc.aio.insecure_channel(IMAGE_ADDR) as ch:
#         stub = image_pb2_grpc.ImageServiceStub(ch)
#         req = image_pb2.ListHistoryRequest(user_id=user_payload["sub"], limit=20, offset=0)
#         metadata = (("authorization", f"Bearer {token}"),)
#         try:
#             resp = await stub.ListHistory(req, metadata=metadata, timeout=10)
#             return [
#                 {
#                     "id": it.id,
#                     "prompt": it.prompt,
#                     "image_url": it.image_url,
#                     "results": json.loads(it.results_json) if it.results_json else None,
#                     "timestamp": it.timestamp,
#                 }
#                 for it in resp.items
#             ]
#         except grpc.aio.AioRpcError as e:
#             raise HTTPException(status_code=502, detail=f"ImageService error: {e.details()}")

# @app.delete("/image/{item_id}")
# async def delete_image(item_id: int, user_info=Depends(get_current_user_for_image)):
#     user_payload, token = user_info
#     async with grpc.aio.insecure_channel(IMAGE_ADDR) as ch:
#         stub = image_pb2_grpc.ImageServiceStub(ch)
#         req = image_pb2.DeleteImageRequest(id=item_id, user_id=user_payload["sub"])
#         metadata = (("authorization", f"Bearer {token}"),)
#         try:
#             resp = await stub.DeleteImage(req, metadata=metadata, timeout=10)
#             if not resp.ok:
#                 raise HTTPException(status_code=400, detail=resp.error or "Delete failed")
#             return {"ok": resp.ok, "message": "deleted"}
#         except grpc.aio.AioRpcError as e:
#             raise HTTPException(status_code=502, detail=f"ImageService error: {e.details()}")

# # ----------------- Root -----------------
# @app.get("/")
# def root():
#     return {
#         "status": "gateway (auth + image)",
#         "auth_service": AUTH_SERVICE_ADDR,
#         "image_service": IMAGE_ADDR,
#     }


import os
import json
import time
import traceback
from typing import Optional, Tuple, List

import grpc
from grpc import StatusCode
from fastapi import FastAPI, Request, Depends, HTTPException, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
from fastapi.responses import JSONResponse
import redis.asyncio as redis

# ----------------- gRPC stubs -----------------
# Primary auth
import auth_access_pb2 as auth_access_pb
import auth_access_pb2_grpc as auth_access_pb_grpc

# Legacy auth (for verification only if needed)
import auth_pb2 as legacy_auth_pb
import auth_pb2_grpc as legacy_auth_pb_grpc

# Search proto
import search_pb2 as search_pb
import search_pb2_grpc as search_pb_grpc

# Image service
import image_pb2, image_pb2_grpc

# MCP client (for /search MCP)
from mcp.client.streamable_http import streamablehttp_client
from mcp.client.session import ClientSession


# ----------------- Config -----------------
AUTH_SERVICE_ADDR = os.environ.get("AUTH_SERVICE_ADDR", "localhost:50054")   # primary auth for /auth endpoints
LEGACY_AUTH_ADDR = os.environ.get("LEGACY_AUTH_ADDR", "localhost:50051")    # legacy auth for /search & image
SEARCH_SERVICE_ADDR = os.environ.get("SEARCH_SERVICE_ADDR", "localhost:50055")
IMAGE_ADDR = os.environ.get("IMAGE_SERVICE_ADDR", "localhost:50057")

MCP_URL = os.environ.get("MCP_URL", "https://server.smithery.ai/@nickclyde/duckduckgo-mcp-server/mcp")
API_KEY = os.environ.get("MCP_API_KEY", "775e8343-7c8c-47b0-8d12-93f9b45c293c")
PROFILE = os.environ.get("MCP_PROFILE", "developing-marten-gJ1abJ")

REDIS_HOST = os.environ.get("REDIS_HOST", "localhost")
REDIS_PORT = int(os.environ.get("REDIS_PORT", 6379))
AUTH_CACHE_TTL = int(os.environ.get("AUTH_CACHE_TTL", 3600))


# ----------------- App -----------------
app = FastAPI(title="Unified Gateway (auth + search + image)")
redis_client = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, decode_responses=True)
security = HTTPBearer()


# ----------------- Pydantic models -----------------
class RegisterIn(BaseModel):
    email: str
    password: str

class LoginIn(BaseModel):
    email: str
    password: str

class RefreshIn(BaseModel):
    refresh_token: str

class TokenOut(BaseModel):
    access_token: str
    refresh_token: str

class ValidateIn(BaseModel):
    token: str

class ValidateOut(BaseModel):
    valid: bool
    user_id: Optional[str]
    role: Optional[str]
    expires_at: Optional[int]
    error: Optional[str]

class HistoryItemOut(BaseModel):
    id: int
    user_id: str
    query: str
    results: List[dict]
    timestamp: str


# ----------------- Startup / Shutdown -----------------
@app.on_event("startup")
async def startup():
    # primary auth_access stub (for /auth endpoints)
    app.state.auth_channel = grpc.aio.insecure_channel(AUTH_SERVICE_ADDR)
    app.state.auth_stub = auth_access_pb_grpc.AuthServiceStub(app.state.auth_channel)

    # legacy auth stub (for /search + /image login/verify)
    app.state.legacy_auth_channel = grpc.aio.insecure_channel(LEGACY_AUTH_ADDR)
    app.state.legacy_auth_stub = legacy_auth_pb_grpc.AuthServiceStub(app.state.legacy_auth_channel)

    # search service stub
    app.state.search_channel = grpc.aio.insecure_channel(SEARCH_SERVICE_ADDR)
    app.state.search_stub = search_pb_grpc.GatewayAuthSearchStub(app.state.search_channel)


@app.on_event("shutdown")
async def shutdown():
    if hasattr(app.state, "auth_channel"):
        await app.state.auth_channel.close()
    if hasattr(app.state, "legacy_auth_channel"):
        await app.state.legacy_auth_channel.close()
    if hasattr(app.state, "search_channel"):
        await app.state.search_channel.close()


# ----------------- Helpers -----------------
def grpc_error_to_http(e: grpc.aio.AioRpcError) -> HTTPException:
    code, details = e.code(), e.details() or ""
    mapping = {
        StatusCode.NOT_FOUND: 404,
        StatusCode.INVALID_ARGUMENT: 400,
        StatusCode.UNAUTHENTICATED: 401,
        StatusCode.PERMISSION_DENIED: 403,
        StatusCode.ALREADY_EXISTS: 409,
        StatusCode.DEADLINE_EXCEEDED: 504,
        StatusCode.UNAVAILABLE: 503,
    }
    if code in mapping:
        return HTTPException(status_code=mapping[code], detail=details or str(code))
    return HTTPException(status_code=500, detail=f"Upstream gRPC error: {details}")


def metadata_from_request(req: Request) -> Tuple[Tuple[str, str], ...]:
    auth = req.headers.get("authorization")
    return (("authorization", auth),) if auth else ()


# --- Token validation ---
async def validate_token_with_primary(token: str):
    cached = await redis_client.get(f"token:{token}")
    if cached:
        return json.loads(cached)

    stub = app.state.auth_stub
    req = auth_access_pb.ValidateTokenRequest(token=token)
    try:
        resp = await stub.ValidateToken(req, timeout=4.0)
    except grpc.aio.AioRpcError as e:
        raise grpc_error_to_http(e)

    if not resp.valid:
        raise HTTPException(status_code=401, detail=resp.error or "Invalid token")

    payload = {"sub": resp.user_id, "role": resp.role}
    expires_at = int(resp.expires_at or 0)
    ttl = (expires_at - int(time.time())) if expires_at > int(time.time()) else AUTH_CACHE_TTL
    await redis_client.setex(f"token:{token}", ttl, json.dumps(payload))
    return payload


async def verify_and_cache_using_legacy(token: str):
    cached = await redis_client.get(f"token:{token}")
    if cached:
        return json.loads(cached)

    stub = app.state.legacy_auth_stub
    req = legacy_auth_pb.VerifyRequest(token=token)
    try:
        resp = await stub.Verify(req, timeout=4.0)
    except grpc.aio.AioRpcError as e:
        raise grpc_error_to_http(e)

    payload = {"sub": resp.sub, "role": getattr(resp, "role", "")}
    await redis_client.setex(f"token:{token}", AUTH_CACHE_TTL, json.dumps(payload))
    return payload


# dynamic dependency: if path startswith /search -> legacy auth; else -> primary
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security), request: Request = None):
    token = credentials.credentials
    if not token:
        raise HTTPException(status_code=401, detail="Authorization token missing")
    path = request.scope.get("path", "") if request else ""
    if path.startswith("/search"):
        return await verify_and_cache_using_legacy(token)
    return await validate_token_with_primary(token)


# ----------------- Auth Endpoints -----------------
@app.post("/auth/register", response_model=TokenOut)
async def register(payload: RegisterIn, request: Request):
    stub = app.state.auth_stub
    resp = await stub.Register(auth_access_pb.RegisterRequest(email=payload.email, password=payload.password),
                               timeout=5.0, metadata=metadata_from_request(request))
    return TokenOut(access_token=resp.access_token, refresh_token=resp.refresh_token)


@app.post("/auth/login", response_model=TokenOut)
async def auth_login(payload: LoginIn, request: Request):
    stub = app.state.auth_stub
    resp = await stub.Login(auth_access_pb.LoginRequest(email=payload.email, password=payload.password),
                            timeout=5.0, metadata=metadata_from_request(request))
    return TokenOut(access_token=resp.access_token, refresh_token=resp.refresh_token)


@app.post("/auth/refresh", response_model=TokenOut)
async def refresh(payload: RefreshIn, request: Request):
    stub = app.state.auth_stub
    resp = await stub.Refresh(auth_access_pb.RefreshRequest(refresh_token=payload.refresh_token),
                              timeout=5.0, metadata=metadata_from_request(request))
    return TokenOut(access_token=resp.access_token, refresh_token=resp.refresh_token)


@app.post("/auth/validate", response_model=ValidateOut)
async def validate(payload: ValidateIn, request: Request):
    stub = app.state.auth_stub
    resp = await stub.ValidateToken(auth_access_pb.ValidateTokenRequest(token=payload.token),
                                    timeout=4.0, metadata=metadata_from_request(request))
    return ValidateOut(
        valid=resp.valid,
        user_id=resp.user_id or None,
        role=resp.role or None,
        expires_at=resp.expires_at or None,
        error=resp.error or None,
    )


# ----------------- Search Endpoints -----------------
# @app.post("/search/login", response_model=TokenOut)
# async def search_login(payload: LoginIn, request: Request):
#     stub = app.state.legacy_auth_stub
#     resp = await stub.Login(legacy_auth_pb.LoginRequest(email=payload.email, password=payload.password),
#                             timeout=5.0, metadata=metadata_from_request(request))
#     try:
#         await verify_and_cache_using_legacy(resp.access_token)
#     except Exception:
#         pass
#     return TokenOut(access_token=resp.access_token, refresh_token=resp.refresh_token)


# @app.post("/search/verify", response_model=ValidateOut)
# async def search_verify(payload: ValidateIn, request: Request):
#     stub = app.state.legacy_auth_stub
#     try:
#         resp = await stub.Verify(legacy_auth_pb.VerifyRequest(token=payload.token),
#                                  timeout=4.0, metadata=metadata_from_request(request))
#         return ValidateOut(valid=True, user_id=resp.sub or None, role=resp.role or None, expires_at=None, error=None)
#     except grpc.aio.AioRpcError as e:
#         if e.code() == grpc.StatusCode.UNAUTHENTICATED:
#             return ValidateOut(valid=False, user_id=None, role=None, expires_at=None, error=e.details())
#         raise grpc_error_to_http(e)


@app.post("/search/", dependencies=[Depends(get_current_user)])
async def perform_search(query: str = Query(...), current_user=Depends(get_current_user)):
    user_id = str(int(current_user.get("sub"))) if current_user.get("sub") else ""
    cache_key = f"search:{user_id}:{query.lower().strip()}"
    cached = await redis_client.get(cache_key)
    if cached:
        return JSONResponse(content=json.loads(cached))

    try:
        url = f"{MCP_URL}?api_key={API_KEY}&profile={PROFILE}"
        async with streamablehttp_client(url) as (read_stream, write_stream, _):
            async with ClientSession(read_stream, write_stream) as sess:
                await sess.initialize()
                tools = await sess.list_tools()
                tool_to_use = "search" if "search" in [t.name for t in tools.tools] else tools.tools[0].name
                res = await sess.call_tool(tool_to_use, {"query": query})
                outputs = res.dict().get("content", [])
                results = [item.get("text") for item in outputs if "text" in item]

        try:
            stub = app.state.search_stub
            pb_results = [search_pb.SearchResult(text=(t or ""), url="") for t in results]
            save_req = search_pb.SaveHistoryRequest(user_id=user_id, query=query, results=pb_results)
            await stub.SaveHistory(save_req, timeout=5.0)
        except Exception as e:
            print("⚠️ SaveHistory error:", e)

        data = {"query": query, "results": results, "user_id": user_id}
        await redis_client.setex(cache_key, 3600, json.dumps(data))
        return JSONResponse(content=data)

    except Exception as e:
        print("⚠️ MCP ERROR TRACE:", traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Search MCP error: {str(e)}")


@app.get("/search/history", response_model=List[HistoryItemOut], dependencies=[Depends(get_current_user)])
async def list_user_searches(limit: int = Query(50), offset: int = Query(0), current_user=Depends(get_current_user)):
    user_id = str(int(current_user.get("sub")))
    stub = app.state.search_stub
    resp = await stub.ListHistory(search_pb.ListHistoryRequest(user_id=user_id, limit=limit, offset=offset), timeout=5.0)

    return [
        HistoryItemOut(
            id=int(it.id),
            user_id=str(it.user_id),
            query=str(it.query),
            results=[{"text": r.text, "url": getattr(r, "url", "")} for r in it.results],
            timestamp=str(it.timestamp),
        )
        for it in resp.items
    ]


@app.delete("/search/{item_id}", dependencies=[Depends(get_current_user)])
async def delete_search_item(item_id: int, current_user=Depends(get_current_user)):
    user_id = str(int(current_user.get("sub")))
    stub = app.state.search_stub
    resp = await stub.DeleteHistory(search_pb.DeleteHistoryRequest(id=item_id, user_id=user_id), timeout=5.0)

    if not getattr(resp, "ok", False):
        raise HTTPException(status_code=400, detail=getattr(resp, "error", "delete failed"))
    return {"message": f"Search history item {item_id} deleted successfully"}


# ----------------- Image Endpoints -----------------
async def grpc_verify(token: str):
    async with grpc.aio.insecure_channel(LEGACY_AUTH_ADDR) as ch:
        stub = legacy_auth_pb_grpc.AuthServiceStub(ch)
        resp = await stub.Verify(legacy_auth_pb.VerifyRequest(token=token), timeout=5)
        return {"sub": resp.sub, "role": getattr(resp, "role", "")}


async def get_current_user_for_image(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = await grpc_verify(token)
    return payload, token


@app.post("/image/generate")
async def generate_image(prompt: str = Query(...), user_info=Depends(get_current_user_for_image)):
    user_payload, token = user_info
    async with grpc.aio.insecure_channel(IMAGE_ADDR) as ch:
        stub = image_pb2_grpc.ImageServiceStub(ch)
        req = image_pb2.GenerateImageRequest(
            user_id=user_payload["sub"], prompt=prompt, model="flux", profile="mixed-viper-NggMmT"
        )
        metadata = (("authorization", f"Bearer {token}"),)
        resp = await stub.GenerateImage(req, metadata=metadata, timeout=120)
        return {
            "ok": resp.ok,
            "message": resp.message,
            "image_url": resp.image_url,
            "results": json.loads(resp.results_json) if resp.results_json else None,
            "id": resp.id,
            "timestamp": resp.timestamp,
        }


@app.get("/image/history")
async def list_history(user_info=Depends(get_current_user_for_image)):
    user_payload, token = user_info
    async with grpc.aio.insecure_channel(IMAGE_ADDR) as ch:
        stub = image_pb2_grpc.ImageServiceStub(ch)
        req = image_pb2.ListHistoryRequest(user_id=user_payload["sub"], limit=20, offset=0)
        metadata = (("authorization", f"Bearer {token}"),)
        resp = await stub.ListHistory(req, metadata=metadata, timeout=10)
        return [
            {
                "id": it.id,
                "prompt": it.prompt,
                "image_url": it.image_url,
                "results": json.loads(it.results_json) if it.results_json else None,
                "timestamp": it.timestamp,
            }
            for it in resp.items
        ]


@app.delete("/image/{item_id}")
async def delete_image(item_id: int, user_info=Depends(get_current_user_for_image)):
    user_payload, token = user_info
    async with grpc.aio.insecure_channel(IMAGE_ADDR) as ch:
        stub = image_pb2_grpc.ImageServiceStub(ch)
        req = image_pb2.DeleteImageRequest(id=item_id, user_id=user_payload["sub"])
        metadata = (("authorization", f"Bearer {token}"),)
        resp = await stub.DeleteImage(req, metadata=metadata, timeout=10)
        if not resp.ok:
            raise HTTPException(status_code=400, detail=resp.error or "Delete failed")
        return {"ok": resp.ok, "message": "deleted"}


# ----------------- Root -----------------
@app.get("/")
def root():
    return {
        "status": "unified gateway",
        "primary_auth": AUTH_SERVICE_ADDR,
        "legacy_auth": LEGACY_AUTH_ADDR,
        "search_grpc": SEARCH_SERVICE_ADDR,
        "image_service": IMAGE_ADDR,
    }
