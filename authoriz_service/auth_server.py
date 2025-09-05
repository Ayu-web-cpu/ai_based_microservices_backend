# auth_server.py
import asyncio
import logging
import os

import grpc
from grpc import aio

# generated stubs (ensure these exist)
import auth_access_pb2 as pb
import auth_access_pb2_grpc as pb_grpc

# project imports
from core import security
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from models.user import User
from db.session import get_session  # make sure this is the same DI used by FastAPI

# -------------------------
# Helper to get DB session
# -------------------------
async def get_db_session() -> AsyncSession:
    """
    Uses your FastAPI-style get_session() async generator to obtain an AsyncSession.
    If your get_session() has a different shape, replace this function accordingly.
    """
    async for session in get_session():
        return session
    raise RuntimeError("get_session did not yield a session")


# -------------------------
# AuthService implementation
# -------------------------
class AuthService(pb_grpc.AuthServiceServicer):
    async def Register(self, request: pb.RegisterRequest, context) -> pb.TokenResponse:
        email, password = request.email or "", request.password or ""
        if not email or not password:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "email and password required")

        db: AsyncSession = await get_db_session()
        result = await db.execute(select(User).where(User.email == email))
        if result.scalar_one_or_none():
            await context.abort(grpc.StatusCode.ALREADY_EXISTS, "Email already registered")

        hashed = security.hash_password(password)
        user = User(email=email, hashed_password=hashed, role="user")
        db.add(user)
        await db.commit()
        await db.refresh(user)

        access = security.create_access_token(str(user.id), user.role)
        refresh = security.create_refresh_token(str(user.id), user.role)
        return pb.TokenResponse(access_token=access, refresh_token=refresh)

    async def Login(self, request: pb.LoginRequest, context) -> pb.TokenResponse:
        email, password = request.email or "", request.password or ""
        if not email or not password:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "email and password required")

        db: AsyncSession = await get_db_session()
        result = await db.execute(select(User).where(User.email == email))
        user = result.scalar_one_or_none()

        if not user or not security.verify_password(password, user.hashed_password):
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid credentials")

        access = security.create_access_token(str(user.id), user.role)
        refresh = security.create_refresh_token(str(user.id), user.role)
        return pb.TokenResponse(access_token=access, refresh_token=refresh)

    async def Refresh(self, request: pb.RefreshRequest, context) -> pb.TokenResponse:
        """
        Accepts a refresh token (request.refresh_token). Mirrors your FastAPI /refresh logic:
        - decode token
        - ensure token type == 'refresh'
        - create new access and refresh tokens
        """
        token = request.refresh_token or ""
        if not token:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "refresh_token required")

        try:
            payload = security.decode_token(token)
            if payload.get("type") != "refresh":
                await context.abort(grpc.StatusCode.UNAUTHENTICATED, "Not a refresh token")
        except Exception as e:
            await context.abort(grpc.StatusCode.UNAUTHENTICATED, f"Invalid refresh token: {e}")

        user_id = payload.get("sub")
        role = payload.get("role", "user")
        access = security.create_access_token(user_id, role)
        refresh = security.create_refresh_token(user_id, role)
        return pb.TokenResponse(access_token=access, refresh_token=refresh)

    async def ValidateToken(self, request: pb.ValidateTokenRequest, context) -> pb.ValidateTokenResponse:
        token = request.token or ""
        if not token:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "token required")

        try:
            payload = security.decode_token(token)
            user_id = str(payload.get("sub", "")) if isinstance(payload, dict) else ""
            role = payload.get("role", "") if isinstance(payload, dict) else ""
            expires_at = int(payload.get("exp", 0)) if isinstance(payload, dict) else 0
            return pb.ValidateTokenResponse(valid=True, user_id=user_id, role=role, expires_at=expires_at, error="")
        except Exception as e:
            return pb.ValidateTokenResponse(valid=False, user_id="", role="", expires_at=0, error=str(e))


# -------------------------
# Server bootstrap
# -------------------------
async def serve(host: str = "[::]", port: int = 50054):
    server = aio.server()
    pb_grpc.add_AuthServiceServicer_to_server(AuthService(), server)

    bind_addr = f"{host}:{port}"
    server.add_insecure_port(bind_addr)
    logging.info(f"Auth gRPC server started on {bind_addr}")
    await server.start()
    await server.wait_for_termination()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    port = int(os.environ.get("AUTH_GRPC_PORT", "50054"))
    asyncio.run(serve(port=port))
