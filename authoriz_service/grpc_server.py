import asyncio
import grpc 
from sqlalchemy import select
import sys, os

# 👇 Add project root for imports
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Import gRPC stubs
from stubs import auth_pb2, auth_pb2_grpc

# Your existing Auth logic
from core import security
from db.session import async_session_maker   # ✅ Use sessionmaker directly
from models.user import User


class AuthService(auth_pb2_grpc.AuthServiceServicer):
    async def Login(self, request, context):
        # ✅ Use async_session_maker instead of get_session
        async with async_session_maker() as db:
            result = await db.execute(select(User).where(User.email == request.email))
            user = result.scalar_one_or_none()

            if not user or not security.verify_password(request.password, user.hashed_password):
                context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid credentials")

            access = security.create_access_token(str(user.id), user.role)
            refresh = security.create_refresh_token(str(user.id), user.role)
            return auth_pb2.TokenResponse(access_token=access, refresh_token=refresh)

    async def Verify(self, request, context):
        try:
            payload = security.decode_token(request.token)
            return auth_pb2.VerifyResponse(
                sub=payload.get("sub"),
                role=payload.get("role")
            )
        except Exception:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid or expired token")


async def serve():
    server = grpc.aio.server()
    auth_pb2_grpc.add_AuthServiceServicer_to_server(AuthService(), server)
    server.add_insecure_port("[::]:50051")
    await server.start()
    print("🚀 Auth gRPC server running on port 50051")
    await server.wait_for_termination()


if __name__ == "__main__":
    asyncio.run(serve())
