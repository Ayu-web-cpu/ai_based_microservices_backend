import asyncio
import grpc
from sqlalchemy import select
import sys, os

# 👇 Add project root for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Import gRPC stubs (gateway proto)
from stubs import gateway_auth_pb2, gateway_auth_pb2_grpc

# Your existing Auth logic
from core import security
from db.session import async_session_maker   # ✅ Use sessionmaker directly
from models.user import User


class GatewayAuthService(gateway_auth_pb2_grpc.AuthServiceServicer):
    # ✅ Register
    async def Register(self, request, context):
        async with async_session_maker() as db:
            result = await db.execute(select(User).where(User.email == request.email))
            user = result.scalar_one_or_none()

            if user:
                context.abort(grpc.StatusCode.ALREADY_EXISTS, "Email already registered")

            hashed = security.hash_password(request.password)
            user = User(email=request.email, hashed_password=hashed, role="user")
            db.add(user)
            await db.commit()
            await db.refresh(user)

            access = security.create_access_token(str(user.id), user.role)
            refresh = security.create_refresh_token(str(user.id), user.role)

            return gateway_auth_pb2.TokenResponse(
                access_token=access,
                refresh_token=refresh
            )

    # ✅ Login
    async def Login(self, request, context):
        async with async_session_maker() as db:
            result = await db.execute(select(User).where(User.email == request.email))
            user = result.scalar_one_or_none()

            if not user or not security.verify_password(request.password, user.hashed_password):
                context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid credentials")

            access = security.create_access_token(str(user.id), user.role)
            refresh = security.create_refresh_token(str(user.id), user.role)

            return gateway_auth_pb2.TokenResponse(
                access_token=access,
                refresh_token=refresh
            )

    # ✅ Refresh
    async def Refresh(self, request, context):
        try:
            payload = security.decode_token(request.refresh_token)
            if payload.get("type") != "refresh":
                raise Exception("Not a refresh token")
        except Exception:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid refresh token")

        user_id, role = payload.get("sub"), payload.get("role", "user")
        access = security.create_access_token(user_id, role)
        refresh = security.create_refresh_token(user_id, role)

        return gateway_auth_pb2.TokenResponse(
            access_token=access,
            refresh_token=refresh
        )


async def serve():
    server = grpc.aio.server()
    gateway_auth_pb2_grpc.add_AuthServiceServicer_to_server(GatewayAuthService(), server)
    server.add_insecure_port("[::]:50052")  # ✅ different port
    await server.start()
    print("🚀 Gateway Auth gRPC server running on port 50052")
    await server.wait_for_termination()


if __name__ == "__main__":
    asyncio.run(serve())
