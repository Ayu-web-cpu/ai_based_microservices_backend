

# import json
# from fastapi import APIRouter, HTTPException, Query, Depends
# from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
# from sqlalchemy.ext.asyncio import AsyncSession
# from sqlalchemy.future import select
# import httpx
# import redis.asyncio as redis

# # Local imports
# from db.session import get_session
# from models.image import ImageHistory

# # MCP client
# from mcp.client.streamable_http import streamablehttp_client
# from mcp.client.session import ClientSession

# # 🔹 MCP Image details
# MCP_IMAGE_URL = "https://server.smithery.ai/@falahgs/flux-imagegen-mcp-server/mcp"
# API_KEY = "73dfbc49-709d-41a2-b868-3ac58a0a2dc4"
# PROFILE = "mixed-viper-NggMmT"

# # 🔹 Redis client
# redis_client = redis.Redis(host="localhost", port=6379, decode_responses=True)

# # 🔹 Auth Service endpoints
# AUTH_LOGIN_URL = "http://localhost:8000/auth/login"
# AUTH_VERIFY_URL = "http://localhost:8000/auth/verify"

# # 🔑 Swagger Security
# security = HTTPBearer()

# # ✅ Login: user enters email + password → get JWT token
# login_router = APIRouter(prefix="/image", tags=["MCP Image (Auth)"])  # Open route

# @login_router.post("/login")
# async def login_user(email: str = Query(...), password: str = Query(...)):
#     async with httpx.AsyncClient() as client:
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
#         await redis_client.setex(f"token:{token}", 3600, json.dumps(user_payload))

#         return {"access_token": token, "token_type": "bearer"}


# # ✅ Helper: get current user
# async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
#     token = credentials.credentials

#     cached = await redis_client.get(f"token:{token}")
#     if cached:
#         return json.loads(cached)

#     async with httpx.AsyncClient() as client:
#         verify = await client.post(AUTH_VERIFY_URL, json={"token": token})
#         if verify.status_code != 200:
#             raise HTTPException(status_code=401, detail="Invalid or expired token")

#     user_payload = verify.json()
#     await redis_client.setex(f"token:{token}", 3600, json.dumps(user_payload))
#     return user_payload


# # 🔒 Protected router
# router = APIRouter(
#     prefix="/image",
#     tags=["MCP Image (Protected)"],
#     dependencies=[Depends(get_current_user)]
# )


# # ✅ Generate Image
# @router.post("/")
# async def generate_image(
#     prompt: str = Query(..., description="Prompt to generate image"),
#     session: AsyncSession = Depends(get_session),
#     current_user=Depends(get_current_user),
# ):
#     user_id = int(current_user["sub"])
#     cache_key = f"image:{user_id}:{prompt.lower().strip()}"

#     cached = await redis_client.get(cache_key)
#     if cached:
#         return json.loads(cached)

#     try:
#         url = f"{MCP_IMAGE_URL}?api_key={API_KEY}&profile={PROFILE}"
#         async with streamablehttp_client(url) as (read_stream, write_stream, _):
#             async with ClientSession(read_stream, write_stream) as sess:
#                 await sess.initialize()

#                 tools = await sess.list_tools()
#                 tool_to_use = "generateImageUrl" if "generateImageUrl" in [t.name for t in tools.tools] else "generateImage"

#                 res = await sess.call_tool(tool_to_use, {"prompt": prompt, "model": "flux"})
#                 outputs = res.dict().get("content", [])

#                 image_url = None
#                 if outputs and isinstance(outputs, list):
#                     try:
#                         parsed = json.loads(outputs[0]["text"])
#                         image_url = parsed.get("imageUrl")
#                     except Exception:
#                         pass

#                 # ✅ Use dict/list directly (not json.dumps)
#                 safe_results = outputs if isinstance(outputs, (list, dict)) else []

#                 # ✅ Save to DB
#                 try:
#                     new_history = ImageHistory(
#                         prompt=prompt,
#                         results=safe_results,
#                         image_url=image_url,
#                         user_id=user_id
#                     )
#                     session.add(new_history)
#                     await session.commit()
#                     await session.refresh(new_history)

#                     data = {
#                         "id": new_history.id,
#                         "prompt": new_history.prompt,
#                         "results": new_history.results,
#                         "image_url": new_history.image_url,
#                         "timestamp": str(new_history.timestamp),
#                         "user_id": new_history.user_id,
#                     }

#                 except Exception as db_err:
#                     await session.rollback()
#                     data = {
#                         "message": "⚠️ DB save failed, but image generated",
#                         "prompt": prompt,
#                         "results": outputs,
#                         "image_url": image_url,
#                         "user_id": user_id,
#                         "error": str(db_err),
#                     }

#                 await redis_client.setex(cache_key, 3600, json.dumps(data))
#                 return data

#     except Exception as e:
#         raise HTTPException(status_code=500, detail=f"Image MCP error: {str(e)}")


# # ✅ List all generated images
# @router.get("/history")
# async def list_user_images(
#     session: AsyncSession = Depends(get_session),
#     current_user=Depends(get_current_user),
# ):
#     user_id = int(current_user["sub"])
#     result = await session.execute(select(ImageHistory).where(ImageHistory.user_id == user_id))
#     items = result.scalars().all()

#     history = []
#     for item in items:
#         try:
#             parsed_results = json.loads(item.results) if isinstance(item.results, str) else item.results
#         except Exception:
#             parsed_results = item.results

#         history.append({
#             "id": item.id,
#             "prompt": item.prompt,
#             "results": parsed_results,
#             "image_url": item.image_url,
#             "timestamp": str(item.timestamp),
#             "user_id": item.user_id,
#         })

#     return history


# # ✅ Delete an image history item (single definition, with cache clear)
# @router.delete("/{item_id}")
# async def delete_image_item(
#     item_id: int,
#     session: AsyncSession = Depends(get_session),
#     current_user=Depends(get_current_user),
# ):
#     user_id = int(current_user["sub"])
#     item = await session.get(ImageHistory, item_id)
#     if not item or item.user_id != user_id:
#         raise HTTPException(status_code=404, detail="Item not found or not yours")

#     await session.delete(item)
#     await session.commit()

#     cache_key = f"image:{user_id}:{item.prompt.lower().strip()}"
#     await redis_client.delete(cache_key)

#     return {
#         "message": f"Image history item {item_id} deleted successfully",
#         "cache_cleared": cache_key
#     }



#     return {"message": f"Search history item {item_id} deleted successfully"}
import sys, os
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))


import json
import grpc
import redis.asyncio as redis
from fastapi import APIRouter, HTTPException, Query, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

# Local imports
from db.session import get_session
from models.image import ImageHistory



from stubs import auth_pb2, auth_pb2_grpc

# MCP client
from mcp.client.streamable_http import streamablehttp_client
from mcp.client.session import ClientSession

# 🔹 MCP Image details
MCP_IMAGE_URL = "https://server.smithery.ai/@falahgs/flux-imagegen-mcp-server/mcp"
API_KEY = "73dfbc49-709d-41a2-b868-3ac58a0a2dc4"
PROFILE = "mixed-viper-NggMmT"

# 🔹 Redis client
redis_client = redis.Redis(host="localhost", port=6379, decode_responses=True)

# 🔑 Swagger Security
security = HTTPBearer()

# 🔹 gRPC helper functions
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

# ✅ Login: user enters email + password → get JWT token via gRPC
login_router = APIRouter(prefix="/image", tags=["MCP Image (Auth)"])

@login_router.post("/login")
async def login_user(email: str = Query(...), password: str = Query(...)):
    resp = await grpc_login(email, password)
    token = resp.access_token

    # Verify immediately via gRPC
    user_payload = await grpc_verify(token)

    await redis_client.setex(f"token:{token}", 3600, json.dumps(user_payload))
    return {"access_token": token, "refresh_token": resp.refresh_token, "token_type": "bearer"}

# ✅ Helper: get current user
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    cached = await redis_client.get(f"token:{token}")
    if cached:
        return json.loads(cached)

    user_payload = await grpc_verify(token)
    await redis_client.setex(f"token:{token}", 3600, json.dumps(user_payload))
    return user_payload

# 🔒 Protected router
router = APIRouter(
    prefix="/image",
    tags=["MCP Image (Protected)"],
    dependencies=[Depends(get_current_user)]
)

# ✅ Generate Image
@router.post("/")
async def generate_image(
    prompt: str = Query(..., description="Prompt to generate image"),
    session: AsyncSession = Depends(get_session),
    current_user=Depends(get_current_user),
):
    user_id = int(current_user["sub"])
    cache_key = f"image:{user_id}:{prompt.lower().strip()}"

    cached = await redis_client.get(cache_key)
    if cached:
        return json.loads(cached)

    try:
        url = f"{MCP_IMAGE_URL}?api_key={API_KEY}&profile={PROFILE}"
        async with streamablehttp_client(url) as (read_stream, write_stream, _):
            async with ClientSession(read_stream, write_stream) as sess:
                await sess.initialize()
                tools = await sess.list_tools()
                tool_to_use = "generateImageUrl" if "generateImageUrl" in [t.name for t in tools.tools] else "generateImage"
                res = await sess.call_tool(tool_to_use, {"prompt": prompt, "model": "flux"})
                outputs = res.dict().get("content", [])

                image_url = None
                if outputs and isinstance(outputs, list):
                    try:
                        parsed = json.loads(outputs[0]["text"])
                        image_url = parsed.get("imageUrl")
                    except Exception:
                        pass

                safe_results = outputs if isinstance(outputs, (list, dict)) else []

                try:
                    new_history = ImageHistory(
                        prompt=prompt,
                        results=safe_results,
                        image_url=image_url,
                        user_id=user_id
                    )
                    session.add(new_history)
                    await session.commit()
                    await session.refresh(new_history)

                    data = {
                        "id": new_history.id,
                        "prompt": new_history.prompt,
                        "results": new_history.results,
                        "image_url": new_history.image_url,
                        "timestamp": str(new_history.timestamp),
                        "user_id": new_history.user_id,
                    }

                except Exception as db_err:
                    await session.rollback()
                    data = {
                        "message": "⚠️ DB save failed, but image generated",
                        "prompt": prompt,
                        "results": outputs,
                        "image_url": image_url,
                        "user_id": user_id,
                        "error": str(db_err),
                    }

                await redis_client.setex(cache_key, 3600, json.dumps(data))
                return data

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Image MCP error: {str(e)}")

# ✅ List all generated images
@router.get("/history")
async def list_user_images(session: AsyncSession = Depends(get_session), current_user=Depends(get_current_user)):
    user_id = int(current_user["sub"])
    result = await session.execute(select(ImageHistory).where(ImageHistory.user_id == user_id))
    items = result.scalars().all()

    history = []
    for item in items:
        try:
            parsed_results = json.loads(item.results) if isinstance(item.results, str) else item.results
        except Exception:
            parsed_results = item.results

        history.append({
            "id": item.id,
            "prompt": item.prompt,
            "results": parsed_results,
            "image_url": item.image_url,
            "timestamp": str(item.timestamp),
            "user_id": item.user_id,
        })

    return history

# ✅ Delete an image history item
@router.delete("/{item_id}")
async def delete_image_item(item_id: int, session: AsyncSession = Depends(get_session), current_user=Depends(get_current_user)):
    user_id = int(current_user["sub"])
    item = await session.get(ImageHistory, item_id)
    if not item or item.user_id != user_id:
        raise HTTPException(status_code=404, detail="Item not found or not yours")

    await session.delete(item)
    await session.commit()

    cache_key = f"image:{user_id}:{item.prompt.lower().strip()}"
    await redis_client.delete(cache_key)

    return {
        "message": f"Image history item {item_id} deleted successfully",
        "cache_cleared": cache_key
    }
