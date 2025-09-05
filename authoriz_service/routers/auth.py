
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from db.session import get_session
from schemas.user import UserCreate, Token
from models.user import User
from core import security
from pydantic import BaseModel
import json, time

# ✅ Redis client
import redis.asyncio as redis
redis_client = redis.Redis(host="localhost", port=6379, decode_responses=True)

class TokenVerifyRequest(BaseModel):
    token: str

router = APIRouter(prefix="/auth", tags=["auth"])


# ✅ Register
@router.post("/register", response_model=Token)
async def register(user_in: UserCreate, db: AsyncSession = Depends(get_session)):
    result = await db.execute(select(User).where(User.email == user_in.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    hashed = security.hash_password(user_in.password)
    user = User(email=user_in.email, hashed_password=hashed, role="user")
    db.add(user)
    await db.commit()
    await db.refresh(user)

    access = security.create_access_token(str(user.id), user.role)
    refresh = security.create_refresh_token(str(user.id), user.role)
    return Token(access_token=access, refresh_token=refresh)


# ✅ Login (JSON-only, aligned with Image Service)
@router.post("/login", response_model=Token)
async def login(user_in: UserCreate, db: AsyncSession = Depends(get_session)):
    result = await db.execute(select(User).where(User.email == user_in.email))
    user = result.scalar_one_or_none()

    if not user or not security.verify_password(user_in.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access = security.create_access_token(str(user.id), user.role)
    refresh = security.create_refresh_token(str(user.id), user.role)
    return Token(access_token=access, refresh_token=refresh)


# ✅ Refresh
@router.post("/refresh", response_model=Token)
async def refresh(token: str):
    try:
        payload = security.decode_token(token)
        if payload.get("type") != "refresh":
            raise HTTPException(status_code=401, detail="Not a refresh token")
    except Exception:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    user_id, role = payload.get("sub"), payload.get("role", "user")
    access = security.create_access_token(user_id, role)
    refresh = security.create_refresh_token(user_id, role)
    return Token(access_token=access, refresh_token=refresh)





# @router.post("/verify")
# async def verify(request: TokenVerifyRequest):
#     cache_key = f"token:{request.token}"

#     # 1️⃣ Check cache
#     cached = await redis_client.get(cache_key)
#     if cached:
#         print(f"🔄 [REDIS HIT] Token served from Redis cache → {request.token[:20]}...")
#         return json.loads(cached)

#     # 2️⃣ Decode if not cached
#     try:
#         payload = security.decode_token(request.token)
#         data = {"sub": payload.get("sub"), "role": payload.get("role")}

#         # 3️⃣ Calculate remaining expiry from JWT
#         exp_timestamp = payload.get("exp")
#         now = int(time.time())
#         ttl = max(0, exp_timestamp - now)

#         if ttl > 0:
#             await redis_client.setex(cache_key, ttl, json.dumps(data))
#             print(f"✅ [CACHE MISS] Token decoded & cached for {ttl} sec → {request.token[:20]}...")

#         return data
#     except Exception:
#         print(f"❌ [INVALID] Token invalid/expired → {request.token[:20]}...")
#         raise HTTPException(status_code=401, detail="Invalid or expired token")