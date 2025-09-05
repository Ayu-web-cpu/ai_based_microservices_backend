# import json, traceback
# from fastapi import APIRouter, HTTPException, Query, Depends
# from sqlalchemy.ext.asyncio import AsyncSession
# from sqlalchemy import select
# from db.session import get_session
# from models.search import SearchHistory
# import httpx
# import redis.asyncio as redis

# # MCP client
# from mcp.client.streamable_http import streamablehttp_client
# from mcp.client.session import ClientSession

# search_router = APIRouter(prefix="/search", tags=["MCP Search"])

# # 🔹 Auth Service endpoints
# AUTH_LOGIN_URL = "http://localhost:8000/auth/login"
# AUTH_VERIFY_URL = "http://localhost:8000/auth/verify"

# # 🔹 MCP Search details
# MCP_URL = "https://server.smithery.ai/@nickclyde/duckduckgo-mcp-server/mcp"
# API_KEY = "775e8343-7c8c-47b0-8d12-93f9b45c293c"
# PROFILE = "developing-marten-gJ1abJ"

# # 🔹 Redis client
# redis_client = redis.Redis(host="localhost", port=6379, decode_responses=True)


# # ✅ Per-user token caching (same as image)
# async def get_or_cache_user(email: str, password: str):
#     cache_key = f"user:{email}"

#     # 1️⃣ Check cache
#     cached = await redis_client.get(cache_key)
#     if cached:
#         print(f"🔄 [REDIS HIT] Auth cache for {email}")
#         return json.loads(cached)

#     # 2️⃣ Call Auth Service
#     async with httpx.AsyncClient() as client:
#         response = await client.post(
#             AUTH_LOGIN_URL,
#             json={"email": email, "password": password},
#             headers={"Content-Type": "application/json"}
#         )
#         if response.status_code != 200:
#             raise HTTPException(status_code=401, detail="Authentication failed")

#         token = response.json()["access_token"]

#         verify = await client.post(
#             AUTH_VERIFY_URL,
#             json={"token": token},
#             headers={"Content-Type": "application/json"}
#         )
#         if verify.status_code != 200:
#             raise HTTPException(status_code=401, detail="Token verification failed")

#         user_payload = verify.json()  # {"sub": user_id, "role": "user"}

#         # Cache for 1 hour
#         data = {"token": token, "payload": user_payload}
#         await redis_client.setex(cache_key, 3600, json.dumps(data))
#         print(f"✅ [CACHE MISS] Cached user {email} for 3600s")

#         return data


# # ✅ Perform search with per-user + per-query caching
# @search_router.get("/")
# async def perform_search(
#     query: str = Query(..., description="Search query"),
#     email: str = Query(..., description="User email"),
#     password: str = Query(..., description="User password"),
#     db: AsyncSession = Depends(get_session),
# ):
#     # 🚀 Get user from cache
#     user_data = await get_or_cache_user(email, password)
#     current_user = user_data["payload"]
#     user_id = int(current_user["sub"])

#     # 🔑 cache key = user + query
#     cache_key = f"search:{user_id}:{query.lower().strip()}"

#     # 1️⃣ Check Redis cache
#     cached = await redis_client.get(cache_key)
#     if cached:
#         print(f"🔄 [REDIS HIT] Search cache for user {user_id}, query '{query}'")
#         return json.loads(cached)

#     # 2️⃣ Not cached → call MCP
#     try:
#         url = f"{MCP_URL}?api_key={API_KEY}&profile={PROFILE}"
#         async with streamablehttp_client(url) as (read_stream, write_stream, _):
#             async with ClientSession(read_stream, write_stream) as sess:
#                 await sess.initialize()

#                 tools = await sess.list_tools()
#                 tool_to_use = "search" if "search" in [t.name for t in tools.tools] else tools.tools[0].name

#                 res = await sess.call_tool(tool_to_use, {"query": query})
#                 outputs = res.dict().get("content", [])

#                 # Extract text-based results
#                 results = []
#                 if outputs and isinstance(outputs, list):
#                     for item in outputs:
#                         if "text" in item:
#                             results.append(item["text"])

#                 # Save to DB
#                 history = SearchHistory(
#                     query=query,
#                     results=json.dumps(results),
#                     meta=json.dumps({"source": "DuckDuckGo MCP"}),
#                     user_id=user_id,
#                 )
#                 db.add(history)
#                 await db.commit()
#                 await db.refresh(history)

#                 response_data = {
#                     "id": history.id,
#                     "query": query,
#                     "results": results,
#                     "timestamp": str(history.timestamp),
#                     "user_id": user_id,
#                 }

#                 # 3️⃣ Cache response (1 hour expiry)
#                 await redis_client.setex(cache_key, 3600, json.dumps(response_data))
#                 print(f"✅ [CACHE MISS] Stored search for user {user_id}, query '{query}'")

#                 return response_data

#     except Exception as e:
#         print("⚠️ MCP ERROR TRACE:", traceback.format_exc())
#         raise HTTPException(status_code=500, detail=f"Search MCP error: {str(e)}")



# import json, traceback
# from fastapi import APIRouter, HTTPException, Query
# import httpx
# import redis.asyncio as redis

# # MCP client
# from mcp.client.streamable_http import streamablehttp_client
# from mcp.client.session import ClientSession

# search_router = APIRouter(prefix="/search", tags=["MCP Search"])

# # 🔹 Auth Service endpoints
# AUTH_LOGIN_URL = "http://localhost:8000/auth/login"
# AUTH_VERIFY_URL = "http://localhost:8000/auth/verify"

# # 🔹 Dashboard Service endpoint
# DASHBOARD_SAVE_URL = "http://localhost:8004/dashboard/"

# # 🔹 MCP Search details
# MCP_URL = "https://server.smithery.ai/@nickclyde/duckduckgo-mcp-server/mcp"
# API_KEY = "775e8343-7c8c-47b0-8d12-93f9b45c293c"
# PROFILE = "developing-marten-gJ1abJ"

# # 🔹 Redis client
# redis_client = redis.Redis(host="localhost", port=6379, decode_responses=True)


# # ✅ Per-user token caching
# async def get_or_cache_user(email: str, password: str):
#     cache_key = f"user:{email}"

#     cached = await redis_client.get(cache_key)
#     if cached:
#         print(f"🔄 [REDIS HIT] Auth cache for {email}")
#         return json.loads(cached)

#     async with httpx.AsyncClient() as client:
#         response = await client.post(
#             AUTH_LOGIN_URL,
#             json={"email": email, "password": password},
#             headers={"Content-Type": "application/json"}
#         )
#         if response.status_code != 200:
#             raise HTTPException(status_code=401, detail="Authentication failed")

#         token = response.json()["access_token"]

#         verify = await client.post(
#             AUTH_VERIFY_URL,
#             json={"token": token},
#             headers={"Content-Type": "application/json"}
#         )
#         if verify.status_code != 200:
#             raise HTTPException(status_code=401, detail="Token verification failed")

#         user_payload = verify.json()
#         data = {"token": token, "payload": user_payload}

#         await redis_client.setex(cache_key, 3600, json.dumps(data))
#         print(f"✅ [CACHE MISS] Cached user {email} for 3600s")

#         return data


# # ✅ Perform search (save to Dashboard with email+password)
# @search_router.get("/")
# async def perform_search(
#     query: str = Query(..., description="Search query"),
#     email: str = Query(..., description="User email"),
#     password: str = Query(..., description="User password"),
# ):
#     # 🚀 Verify user
#     user_data = await get_or_cache_user(email, password)
#     current_user = user_data["payload"]
#     user_id = int(current_user["sub"])

#     cache_key = f"search:{user_id}:{query.lower().strip()}"

#     # 1️⃣ Redis cache check
#     cached = await redis_client.get(cache_key)
#     if cached:
#         print(f"🔄 [REDIS HIT] Search cache for user {user_id}, query '{query}'")
#         return json.loads(cached)

#     # 2️⃣ Not cached → call MCP
#     try:
#         url = f"{MCP_URL}?api_key={API_KEY}&profile={PROFILE}"
#         async with streamablehttp_client(url) as (read_stream, write_stream, _):
#             async with ClientSession(read_stream, write_stream) as sess:
#                 await sess.initialize()

#                 tools = await sess.list_tools()
#                 tool_to_use = "search" if "search" in [t.name for t in tools.tools] else tools.tools[0].name

#                 res = await sess.call_tool(tool_to_use, {"query": query})
#                 outputs = res.dict().get("content", [])

#                 # Extract text-based results
#                 results = []
#                 if outputs and isinstance(outputs, list):
#                     for item in outputs:
#                         if "text" in item:
#                             results.append(item["text"])

#                 # 3️⃣ Save to Dashboard Service (email & password)
#                 async with httpx.AsyncClient() as client:
#                     dashboard_payload = {
#                         "item_type": "search",
#                         "title": query,
#                         "content": json.dumps(results),
#                         "name": None
#                     }
#                     dash_resp = await client.post(
#                         f"{DASHBOARD_SAVE_URL}?email={email}&password={password}",
#                         json=dashboard_payload
#                     )

#                 if dash_resp.status_code != 200:
#                     raise HTTPException(status_code=500, detail="Failed to save to Dashboard")

#                 saved_item = dash_resp.json()

#                 # 4️⃣ Cache response
#                 await redis_client.setex(cache_key, 3600, json.dumps(saved_item))
#                 print(f"✅ [CACHE MISS] Stored search for user {user_id}, query '{query}'")

#                 return saved_item

#     except Exception as e:
#         print("⚠️ MCP ERROR TRACE:", traceback.format_exc())
#         raise HTTPException(status_code=500, detail=f"Search MCP error: {str(e)}")


# import json, traceback
# from fastapi import APIRouter, HTTPException, Query, Depends
# import redis.asyncio as redis
# from sqlalchemy.ext.asyncio import AsyncSession
# from sqlalchemy.future import select
# import httpx

# # Local imports
# from db.session import get_session
# from models.search import SearchHistory

# # MCP client
# from mcp.client.streamable_http import streamablehttp_client
# from mcp.client.session import ClientSession

# search_router = APIRouter(prefix="/search", tags=["MCP Search"])

# # 🔹 MCP Search details
# MCP_URL = "https://server.smithery.ai/@nickclyde/duckduckgo-mcp-server/mcp"
# API_KEY = "775e8343-7c8c-47b0-8d12-93f9b45c293c"
# PROFILE = "developing-marten-gJ1abJ"

# # 🔹 Redis client
# redis_client = redis.Redis(host="localhost", port=6379, decode_responses=True)

# # 🔹 Auth Service endpoints
# AUTH_LOGIN_URL = "http://localhost:8000/auth/login"
# AUTH_VERIFY_URL = "http://localhost:8000/auth/verify"


# # ✅ Per-user token caching
# async def get_or_cache_user(email: str, password: str):
#     cache_key = f"user:{email}"

#     cached = await redis_client.get(cache_key)
#     if cached:
#         print(f"🔄 [REDIS HIT] Auth cache for {email}")
#         return json.loads(cached)

#     async with httpx.AsyncClient() as client:
#         # login
#         resp = await client.post(
#             AUTH_LOGIN_URL,
#             json={"email": email, "password": password},
#             headers={"Content-Type": "application/json"}
#         )
#         if resp.status_code != 200:
#             raise HTTPException(status_code=401, detail="Authentication failed")

#         token = resp.json()["access_token"]

#         # verify
#         verify = await client.post(AUTH_VERIFY_URL, json={"token": token})
#         if verify.status_code != 200:
#             raise HTTPException(status_code=401, detail="Token verification failed")

#         user_payload = verify.json()
#         data = {"token": token, "payload": user_payload}

#         # cache 1 hour
#         await redis_client.setex(cache_key, 3600, json.dumps(data))
#         print(f"✅ [CACHE MISS] Cached user {email} for 3600s")

#         return data


# # ✅ Perform search + Save to SearchHistory
# @search_router.get("/")
# async def perform_search(
#     query: str = Query(..., description="Search query"),
#     email: str = Query(..., description="User email"),
#     password: str = Query(..., description="User password"),
#     session: AsyncSession = Depends(get_session),
# ):
#     # 🚀 Authenticate user
#     user_data = await get_or_cache_user(email, password)
#     current_user = user_data["payload"]
#     user_id = int(current_user["sub"])

#     cache_key = f"search:{user_id}:{query.lower().strip()}"

#     # 1️⃣ Redis cache check
#     cached = await redis_client.get(cache_key)
#     if cached:
#         print(f"🔄 [REDIS HIT] Search cache for user {user_id}, query '{query}'")
#         return json.loads(cached)

#     # 2️⃣ Not cached → call MCP
#     try:
#         url = f"{MCP_URL}?api_key={API_KEY}&profile={PROFILE}"
#         async with streamablehttp_client(url) as (read_stream, write_stream, _):
#             async with ClientSession(read_stream, write_stream) as sess:
#                 await sess.initialize()

#                 tools = await sess.list_tools()
#                 tool_to_use = "search" if "search" in [t.name for t in tools.tools] else tools.tools[0].name

#                 res = await sess.call_tool(tool_to_use, {"query": query})
#                 outputs = res.dict().get("content", [])

#                 # Extract text-based results
#                 results = []
#                 if outputs and isinstance(outputs, list):
#                     for item in outputs:
#                         if "text" in item:
#                             results.append(item["text"])

#                 # 3️⃣ Save into DB (SearchHistory)
#                 new_history = SearchHistory(
#                     query=query,
#                     results=results,  # JSON column
#                     meta=None,
#                     user_id=user_id
#                 )
#                 session.add(new_history)
#                 await session.commit()
#                 await session.refresh(new_history)

#                 data = {
#                     "id": new_history.id,
#                     "query": new_history.query,
#                     "results": new_history.results,
#                     "meta": new_history.meta,
#                     "timestamp": str(new_history.timestamp),
#                     "user_id": new_history.user_id,
#                 }

#                 # 4️⃣ Cache response
#                 await redis_client.setex(cache_key, 3600, json.dumps(data))
#                 print(f"✅ [CACHE MISS] Stored search for user {user_id}, query '{query}'")

#                 return data

#     except Exception as e:
#         print("⚠️ MCP ERROR TRACE:", traceback.format_exc())
#         raise HTTPException(status_code=500, detail=f"Search MCP error: {str(e)}")


# # ✅ List all search history for current user
# @search_router.get("/history")
# async def list_user_history(
#     email: str = Query(...),
#     password: str = Query(...),
#     session: AsyncSession = Depends(get_session),
# ):
#     user_data = await get_or_cache_user(email, password)
#     user_id = int(user_data["payload"]["sub"])

#     result = await session.execute(select(SearchHistory).where(SearchHistory.user_id == user_id))
#     items = result.scalars().all()
#     return [
#         {
#             "id": item.id,
#             "query": item.query,
#             "results": item.results,
#             "meta": item.meta,
#             "timestamp": str(item.timestamp),
#             "user_id": item.user_id,
#         }
#         for item in items
#     ]


# # ✅ Update a search history item
# @search_router.put("/{item_id}")
# async def update_history_item(
#     item_id: int,
#     payload: dict,
#     email: str = Query(...),
#     password: str = Query(...),
#     session: AsyncSession = Depends(get_session),
# ):
#     user_data = await get_or_cache_user(email, password)
#     user_id = int(user_data["payload"]["sub"])

#     item = await session.get(SearchHistory, item_id)
#     if not item or item.user_id != user_id:
#         raise HTTPException(status_code=404, detail="Item not found or not yours")

#     item.query = payload.get("query", item.query)
#     item.results = payload.get("results", item.results)
#     item.meta = payload.get("meta", item.meta)

#     session.add(item)
#     await session.commit()
#     await session.refresh(item)

#     return {
#         "id": item.id,
#         "query": item.query,
#         "results": item.results,
#         "meta": item.meta,
#         "timestamp": str(item.timestamp),
#         "user_id": item.user_id,
#     }


# # ✅ Delete a search history item
# @search_router.delete("/{item_id}")
# async def delete_history_item(
#     item_id: int,
#     email: str = Query(...),
#     password: str = Query(...),
#     session: AsyncSession = Depends(get_session),
# ):
#     user_data = await get_or_cache_user(email, password)
#     user_id = int(user_data["payload"]["sub"])

#     item = await session.get(SearchHistory, item_id)
#     if not item or item.user_id != user_id:
#         raise HTTPException(status_code=404, detail="Item not found or not yours")

#     await session.delete(item)
#     await session.commit()

#     return {"message": f"Search history item {item_id} deleted successfully"}
import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))


import json, traceback
import grpc
import redis.asyncio as redis
from fastapi import APIRouter, HTTPException, Query, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

# Local imports
from db.session import get_session
from models.search import SearchHistory

# 🔹 Auth gRPC stubs
from stubs import auth_pb2, auth_pb2_grpc

# 🔹 MCP client
from mcp.client.streamable_http import streamablehttp_client
from mcp.client.session import ClientSession

# 🔹 MCP Search details
MCP_URL = "https://server.smithery.ai/@nickclyde/duckduckgo-mcp-server/mcp"
API_KEY = "775e8343-7c8c-47b0-8d12-93f9b45c293c"
PROFILE = "developing-marten-gJ1abJ"

# 🔹 Redis client
redis_client = redis.Redis(host="localhost", port=6379, decode_responses=True)

# 🔑 Swagger Security
security = HTTPBearer()


# ============================================================
# gRPC Auth helper functions
# ============================================================

async def grpc_login(email: str, password: str):
    async with grpc.aio.insecure_channel("localhost:50051") as channel:
        stub = auth_pb2_grpc.AuthServiceStub(channel)
        try:
            resp = await stub.Login(auth_pb2.LoginRequest(email=email, password=password))
            return resp
        except grpc.aio.AioRpcError as e:
            raise HTTPException(status_code=401, detail=f"Auth failed: {e.details()}")


async def grpc_verify(token: str):
    async with grpc.aio.insecure_channel("localhost:50051") as channel:
        stub = auth_pb2_grpc.AuthServiceStub(channel)
        try:
            resp = await stub.Verify(auth_pb2.VerifyRequest(token=token))
            return {"sub": resp.sub, "role": resp.role}
        except grpc.aio.AioRpcError as e:
            raise HTTPException(status_code=401, detail=f"Token invalid: {e.details()}")


# ============================================================
# Auth routes
# ============================================================

search_router = APIRouter(prefix="/search", tags=["MCP Search (Auth)"])


@search_router.post("/login")
async def login_user(email: str = Query(...), password: str = Query(...)):
    resp = await grpc_login(email, password)
    token = resp.access_token

    # verify immediately
    user_payload = await grpc_verify(token)

    await redis_client.setex(f"token:{token}", 3600, json.dumps(user_payload))
    return {"access_token": token, "refresh_token": resp.refresh_token, "token_type": "bearer"}


async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    cached = await redis_client.get(f"token:{token}")
    if cached:
        return json.loads(cached)

    user_payload = await grpc_verify(token)
    await redis_client.setex(f"token:{token}", 3600, json.dumps(user_payload))
    return user_payload


# ============================================================
# Protected Search routes
# ============================================================

router = APIRouter(
    prefix="/search",
    tags=["MCP Search (Protected)"],
    dependencies=[Depends(get_current_user)]
)


# ✅ Perform search
@router.post("/")
async def perform_search(
    query: str = Query(..., description="Search query"),
    session: AsyncSession = Depends(get_session),
    current_user=Depends(get_current_user),
):
    user_id = int(current_user["sub"])
    cache_key = f"search:{user_id}:{query.lower().strip()}"

    cached = await redis_client.get(cache_key)
    if cached:
        return json.loads(cached)

    try:
        # 🚀 Call MCP
        url = f"{MCP_URL}?api_key={API_KEY}&profile={PROFILE}"
        async with streamablehttp_client(url) as (read_stream, write_stream, _):
            async with ClientSession(read_stream, write_stream) as sess:
                await sess.initialize()

                tools = await sess.list_tools()
                tool_to_use = "search" if "search" in [t.name for t in tools.tools] else tools.tools[0].name

                res = await sess.call_tool(tool_to_use, {"query": query})
                outputs = res.dict().get("content", [])

                # Extract results
                results = [item["text"] for item in outputs if "text" in item]

        # ✅ Save to DB
        try:
            new_history = SearchHistory(
                query=query,
                results=results,
                meta=None,
                user_id=user_id
            )
            session.add(new_history)
            await session.commit()
            await session.refresh(new_history)

            data = {
                "id": new_history.id,
                "query": new_history.query,
                "results": new_history.results,
                "meta": new_history.meta,
                "timestamp": str(new_history.timestamp),
                "user_id": new_history.user_id,
            }

        except Exception as db_err:
            await session.rollback()
            data = {
                "message": "⚠️ DB save failed, but search done",
                "query": query,
                "results": results,
                "user_id": user_id,
                "error": str(db_err),
            }

        await redis_client.setex(cache_key, 3600, json.dumps(data))
        return data

    except Exception as e:
        print("⚠️ MCP ERROR TRACE:", traceback.format_exc())
        raise HTTPException(status_code=500, detail=f"Search MCP error: {str(e)}")


# ✅ List all search history
@router.get("/history")
async def list_user_searches(session: AsyncSession = Depends(get_session), current_user=Depends(get_current_user)):
    user_id = int(current_user["sub"])
    result = await session.execute(select(SearchHistory).where(SearchHistory.user_id == user_id))
    items = result.scalars().all()

    history = []
    for item in items:
        try:
            parsed_results = json.loads(item.results) if isinstance(item.results, str) else item.results
        except Exception:
            parsed_results = item.results

        history.append({
            "id": item.id,
            "query": item.query,
            "results": parsed_results,
            "meta": item.meta,
            "timestamp": str(item.timestamp),
            "user_id": item.user_id,
        })

    return history


# ✅ Delete a search history item
@router.delete("/{item_id}")
async def delete_search_item(item_id: int, session: AsyncSession = Depends(get_session), current_user=Depends(get_current_user)):
    user_id = int(current_user["sub"])
    item = await session.get(SearchHistory, item_id)
    if not item or item.user_id != user_id:
        raise HTTPException(status_code=404, detail="Item not found or not yours")

    await session.delete(item)
    await session.commit()

    cache_key = f"search:{user_id}:{item.query.lower().strip()}"
    await redis_client.delete(cache_key)

    return {
        "message": f"Search history item {item_id} deleted successfully",
        "cache_cleared": cache_key
    }
