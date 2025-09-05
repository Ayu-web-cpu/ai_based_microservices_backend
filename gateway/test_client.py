import json
import grpc
from fastapi import FastAPI, Depends, HTTPException, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# gRPC stubs
import auth_pb2, auth_pb2_grpc
import image_pb2, image_pb2_grpc


AUTH_ADDR = "localhost:50051"
IMAGE_ADDR = "localhost:50057"

app = FastAPI(title="Gateway API", version="1.0")

# JWT security
security = HTTPBearer()


# ---------------------------
# gRPC helpers
# ---------------------------
async def grpc_login(email: str, password: str):
    async with grpc.aio.insecure_channel(AUTH_ADDR) as ch:
        stub = auth_pb2_grpc.AuthServiceStub(ch)
        try:
            resp = await stub.Login(auth_pb2.LoginRequest(email=email, password=password), timeout=10)
            return resp
        except grpc.aio.AioRpcError as e:
            raise HTTPException(status_code=401, detail=f"Login failed: {e.details()}")


async def grpc_verify(token: str):
    async with grpc.aio.insecure_channel(AUTH_ADDR) as ch:
        stub = auth_pb2_grpc.AuthServiceStub(ch)
        try:
            resp = await stub.Verify(auth_pb2.VerifyRequest(token=token), timeout=5)
            return {"sub": resp.sub, "role": resp.role}
        except grpc.aio.AioRpcError as e:
            raise HTTPException(status_code=401, detail=f"Token invalid: {e.details()}")


# ---------------------------
# Dependency: get current user
# ---------------------------
async def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)):
    token = credentials.credentials
    payload = await grpc_verify(token)
    return payload, token


# ---------------------------
# Routes
# ---------------------------

@app.post("/login")
async def login(email: str = Query(...), password: str = Query(...)):
    resp = await grpc_login(email, password)
    return {
        "access_token": resp.access_token,
        "refresh_token": resp.refresh_token,
        "token_type": "bearer"
    }


@app.post("/image/generate")
async def generate_image(
    prompt: str = Query(..., description="Prompt for image generation"),
    user_info=Depends(get_current_user),
):
    user_payload, token = user_info
    async with grpc.aio.insecure_channel(IMAGE_ADDR) as ch:
        stub = image_pb2_grpc.ImageServiceStub(ch)
        req = image_pb2.GenerateImageRequest(
            user_id=user_payload["sub"],
            prompt=prompt,
            model="flux",
            profile="mixed-viper-NggMmT"
        )
        metadata = (("authorization", f"Bearer {token}"),)
        try:
            resp = await stub.GenerateImage(req, metadata=metadata, timeout=120)
            return {
                "ok": resp.ok,
                "message": resp.message,
                "image_url": resp.image_url,
                "results": json.loads(resp.results_json) if resp.results_json else None,
                "id": resp.id,
                "timestamp": resp.timestamp,
            }
        except grpc.aio.AioRpcError as e:
            raise HTTPException(status_code=502, detail=f"ImageService error: {e.details()}")


@app.get("/image/history")
async def list_history(user_info=Depends(get_current_user)):
    user_payload, token = user_info
    async with grpc.aio.insecure_channel(IMAGE_ADDR) as ch:
        stub = image_pb2_grpc.ImageServiceStub(ch)
        req = image_pb2.ListHistoryRequest(user_id=user_payload["sub"], limit=20, offset=0)
        metadata = (("authorization", f"Bearer {token}"),)
        try:
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
        except grpc.aio.AioRpcError as e:
            raise HTTPException(status_code=502, detail=f"ImageService error: {e.details()}")


@app.delete("/image/{item_id}")
async def delete_image(item_id: int, user_info=Depends(get_current_user)):
    user_payload, token = user_info
    async with grpc.aio.insecure_channel(IMAGE_ADDR) as ch:
        stub = image_pb2_grpc.ImageServiceStub(ch)
        req = image_pb2.DeleteImageRequest(id=item_id, user_id=user_payload["sub"])
        metadata = (("authorization", f"Bearer {token}"),)
        try:
            resp = await stub.DeleteImage(req, metadata=metadata, timeout=10)
            if not resp.ok:
                raise HTTPException(status_code=400, detail=resp.error or "Delete failed")
            return {"ok": resp.ok, "message": "deleted"}
        except grpc.aio.AioRpcError as e:
            raise HTTPException(status_code=502, detail=f"ImageService error: {e.details()}")
