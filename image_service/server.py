# import asyncio
# import json
# import logging
# from typing import Optional, List

# import grpc
# from grpc import aio

# # generated from image.proto
# import image_pb2 as img_pb2
# import image_pb2_grpc as img_grpc

# # auth gRPC stubs
# import auth_pb2, auth_pb2_grpc

# # MCP client pieces (from your project)
# from mcp.client.streamable_http import streamablehttp_client
# from mcp.client.session import ClientSession

# # Constants
# MCP_IMAGE_URL = "https://server.smithery.ai/@falahgs/flux-imagegen-mcp-server/mcp"
# API_KEY = "73dfbc49-709d-41a2-b868-3ac58a0a2dc4"
# PROFILE = "mixed-viper-NggMmT"

# LOG = logging.getLogger("image_service")
# logging.basicConfig(level=logging.INFO)


# # --------------------------
# # Metadata token extraction
# # --------------------------
# def extract_bearer_from_metadata(context: aio.ServicerContext) -> Optional[str]:
#     md = dict(context.invocation_metadata() or [])
#     auth = md.get("authorization") or md.get("Authorization")
#     if not auth:
#         return None
#     if auth.lower().startswith("bearer "):
#         return auth.split(" ", 1)[1].strip()
#     return None


# # --------------------------
# # ImageService Implementation
# # --------------------------
# class ImageService(img_grpc.ImageServiceServicer):
#     async def _call_mcp_generate(self, prompt: str) -> (Optional[str], List):
#         """Call MCP to generate an image, return (image_url, outputs)."""
#         url = f"{MCP_IMAGE_URL}?api_key={API_KEY}&profile={PROFILE}"
#         async with streamablehttp_client(url) as (read_stream, write_stream, _):
#             async with ClientSession(read_stream, write_stream) as sess:
#                 await sess.initialize()
#                 tools = await sess.list_tools()
#                 tool_names = [t.name for t in (tools.tools or [])]
#                 tool_to_use = "generateImageUrl" if "generateImageUrl" in tool_names else "generateImage"
#                 res = await sess.call_tool(tool_to_use, {"prompt": prompt, "model": "flux"})
#                 outputs = res.dict().get("content", [])
#                 image_url = None
#                 if outputs and isinstance(outputs, list):
#                     try:
#                         parsed = json.loads(outputs[0].get("text", "{}"))
#                         image_url = parsed.get("imageUrl")
#                     except Exception:
#                         LOG.debug("Could not parse MCP output text as JSON", exc_info=True)
#                 return image_url, outputs

#     async def _verify_token_with_authsvc(self, token: str, auth_addr: str = "localhost:50051") -> Optional[dict]:
#         """Verify JWT with AuthService.Verify RPC. Return payload dict or None."""
#         if not token:
#             return None

#         try:
#             async with grpc.aio.insecure_channel(auth_addr) as ch:
#                 stub = auth_pb2_grpc.AuthServiceStub(ch)
#                 resp = await stub.Verify(auth_pb2.VerifyRequest(token=token), timeout=5.0)

#                 if hasattr(resp, "valid") and not resp.valid:
#                     LOG.warning("Auth service reported invalid token: %s", getattr(resp, "error", ""))
#                     return None

#                 if not getattr(resp, "sub", None):
#                     LOG.warning("Auth verify returned empty sub")
#                     return None

#                 return {"sub": resp.sub, "role": getattr(resp, "role", "")}

#         except grpc.aio.AioRpcError as e:
#             LOG.error("Auth service gRPC error: %s - %s", e.code().name, e.details())
#             return None
#         except Exception:
#             LOG.exception("Unexpected error calling auth service")
#             return None

#     # --------------------------
#     # RPC: GenerateImage
#     # --------------------------
#     async def GenerateImage(self, request: img_pb2.GenerateImageRequest, context: aio.ServicerContext) -> img_pb2.GenerateImageResponse:
#         LOG.info("GenerateImage called with prompt=%s", request.prompt)

#         # extract + verify token
#         token = extract_bearer_from_metadata(context)
#         user_payload = await self._verify_token_with_authsvc(token)
#         if user_payload is None:
#             context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid or missing token")

#         user_id = int(user_payload.get("sub", 0))

#         # call MCP
#         try:
#             image_url, outputs = await self._call_mcp_generate(request.prompt)
#         except Exception as e:
#             context.abort(grpc.StatusCode.INTERNAL, f"MCP error: {e}")

#         # save to DB (TODO: hook real DB)
#         saved_item_proto = img_pb2.ImageHistoryItem(
#             id=0,
#             user_id=str(user_id),
#             prompt=request.prompt,
#             image_url=image_url or "",
#             results_json=json.dumps(outputs or []),
#             timestamp="",  # fill with real timestamp when saving to DB
#         )

#         return img_pb2.GenerateImageResponse(
#             ok=True,
#             message="image generated",
#             image_url=image_url or "",
#             results_json=json.dumps(outputs or []),
#             id=saved_item_proto.id,
#             timestamp=saved_item_proto.timestamp,
#         )

#     # --------------------------
#     # RPC: ListHistory
#     # --------------------------
#     async def ListHistory(self, request: img_pb2.ListHistoryRequest, context: aio.ServicerContext) -> img_pb2.ListHistoryResponse:
#         LOG.info("ListHistory called for user_id=%s", request.user_id)

#         # verify token
#         token = extract_bearer_from_metadata(context)
#         user_payload = await self._verify_token_with_authsvc(token)
#         if user_payload is None:
#             context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid or missing token")

#         # TODO: replace with DB query
#         items = [
#             img_pb2.ImageHistoryItem(
#                 id=1,
#                 user_id=request.user_id,
#                 prompt="example prompt",
#                 image_url="https://example.com/image.png",
#                 results_json=json.dumps([]),
#                 timestamp="2025-09-05T12:00:00Z",
#             )
#         ]
#         return img_pb2.ListHistoryResponse(items=items, total=len(items))

#     # --------------------------
#     # RPC: DeleteImage
#     # --------------------------
#     async def DeleteImage(self, request: img_pb2.DeleteImageRequest, context: aio.ServicerContext) -> img_pb2.DeleteImageResponse:
#         LOG.info("DeleteImage called id=%s user_id=%s", request.id, request.user_id)

#         # verify token
#         token = extract_bearer_from_metadata(context)
#         user_payload = await self._verify_token_with_authsvc(token)
#         if user_payload is None:
#             context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid or missing token")

#         # TODO: perform DB delete
#         return img_pb2.DeleteImageResponse(ok=True, error="")


# # --------------------------
# # gRPC server entrypoint
# # --------------------------
# async def serve(host="0.0.0.0", port=50057):
#     server = aio.server()
#     img_grpc.add_ImageServiceServicer_to_server(ImageService(), server)
#     listen_addr = f"{host}:{port}"
#     server.add_insecure_port(listen_addr)
#     LOG.info("🚀 Starting ImageService gRPC server on %s", listen_addr)
#     await server.start()
#     await server.wait_for_termination()


# if __name__ == "__main__":
#     try:
#         asyncio.run(serve())
#     except KeyboardInterrupt:
#         LOG.info("Server stopped by user")


import asyncio
import json
import logging
from typing import Optional, List
from datetime import datetime

import grpc
from grpc import aio
from sqlalchemy import select

# generated from image.proto
import image_pb2 as img_pb2
import image_pb2_grpc as img_grpc

# auth gRPC stubs
import auth_pb2, auth_pb2_grpc

# DB session + model
from db.session import async_session_maker
from models.image import ImageHistory

# MCP client pieces
from mcp.client.streamable_http import streamablehttp_client
from mcp.client.session import ClientSession

# Constants
MCP_IMAGE_URL = "https://server.smithery.ai/@falahgs/flux-imagegen-mcp-server/mcp"
API_KEY = "73dfbc49-709d-41a2-b868-3ac58a0a2dc4"
PROFILE = "mixed-viper-NggMmT"

LOG = logging.getLogger("image_service")
logging.basicConfig(level=logging.INFO)


# --------------------------
# Metadata token extraction
# --------------------------
def extract_bearer_from_metadata(context: aio.ServicerContext) -> Optional[str]:
    md = dict(context.invocation_metadata() or [])
    auth = md.get("authorization") or md.get("Authorization")
    if not auth:
        return None
    if auth.lower().startswith("bearer "):
        return auth.split(" ", 1)[1].strip()
    return None


# --------------------------
# ImageService Implementation
# --------------------------
class ImageService(img_grpc.ImageServiceServicer):
    async def _call_mcp_generate(self, prompt: str) -> (Optional[str], List):
        """Call MCP to generate an image, return (image_url, outputs)."""
        url = f"{MCP_IMAGE_URL}?api_key={API_KEY}&profile={PROFILE}"
        async with streamablehttp_client(url) as (read_stream, write_stream, _):
            async with ClientSession(read_stream, write_stream) as sess:
                await sess.initialize()
                tools = await sess.list_tools()
                tool_names = [t.name for t in (tools.tools or [])]
                tool_to_use = "generateImageUrl" if "generateImageUrl" in tool_names else "generateImage"

                res = await sess.call_tool(tool_to_use, {"prompt": prompt, "model": "flux"})

                # ✅ Guard against None and log raw response
                res_dict = res.dict() if res is not None else {}
                LOG.debug("MCP raw response dict: %s", json.dumps(res_dict, indent=2, default=str))

                outputs = res_dict.get("content", []) if isinstance(res_dict, dict) else []

                image_url = None
                if outputs and isinstance(outputs, list):
                    try:
                        first = outputs[0]
                        if isinstance(first, dict) and "text" in first:
                            parsed = json.loads(first["text"])
                            LOG.debug("Parsed MCP JSON: %s", parsed)
                            image_url = parsed.get("imageUrl")
                    except Exception:
                        LOG.debug("Could not parse MCP output text as JSON", exc_info=True)

                return image_url, outputs

    async def _verify_token_with_authsvc(self, token: str, auth_addr: str = "localhost:50051") -> Optional[dict]:
        """Verify JWT with AuthService.Verify RPC. Return payload dict or None."""
        if not token:
            return None

        try:
            async with grpc.aio.insecure_channel(auth_addr) as ch:
                stub = auth_pb2_grpc.AuthServiceStub(ch)
                resp = await stub.Verify(auth_pb2.VerifyRequest(token=token), timeout=5.0)
                if hasattr(resp, "valid") and not resp.valid:
                    return None
                if not getattr(resp, "sub", None):
                    return None
                return {"sub": resp.sub, "role": getattr(resp, "role", "")}
        except grpc.aio.AioRpcError as e:
            LOG.error("Auth service gRPC error: %s - %s", e.code().name, e.details())
            return None

    # --------------------------
    # RPC: GenerateImage
    # --------------------------
    async def GenerateImage(self, request: img_pb2.GenerateImageRequest, context: aio.ServicerContext) -> img_pb2.GenerateImageResponse:
        LOG.info("GenerateImage called with prompt=%s", request.prompt)

        # verify token
        token = extract_bearer_from_metadata(context)
        user_payload = await self._verify_token_with_authsvc(token)
        if user_payload is None:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid or missing token")

        user_id = int(user_payload.get("sub", 0))

        # call MCP
        try:
            image_url, outputs = await self._call_mcp_generate(request.prompt)
        except Exception as e:
            LOG.error("MCP call failed: %s", e, exc_info=True)
            context.abort(grpc.StatusCode.INTERNAL, f"MCP error: {e}")

        # save in DB
        async with async_session_maker() as db:
            try:
                new_history = ImageHistory(
                    prompt=request.prompt,
                    results=outputs,
                    image_url=image_url,
                    user_id=user_id,
                    timestamp=datetime.utcnow(),
                )
                db.add(new_history)
                await db.commit()
                await db.refresh(new_history)
                LOG.info("Saved image history id=%s", new_history.id)
            except Exception as e:
                await db.rollback()
                LOG.error("DB error while saving image: %s", e, exc_info=True)
                context.abort(grpc.StatusCode.INTERNAL, f"DB error: {e}")

        return img_pb2.GenerateImageResponse(
            ok=True,
            message="image generated",
            image_url=image_url or "",
            results_json=json.dumps(outputs or []),
            id=new_history.id,
            timestamp=str(new_history.timestamp),
        )

    # --------------------------
    # RPC: ListHistory
    # --------------------------
    async def ListHistory(self, request: img_pb2.ListHistoryRequest, context: aio.ServicerContext) -> img_pb2.ListHistoryResponse:
        LOG.info("ListHistory called for user_id=%s", request.user_id)

        # verify token
        token = extract_bearer_from_metadata(context)
        user_payload = await self._verify_token_with_authsvc(token)
        if user_payload is None:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid or missing token")

        async with async_session_maker() as db:
            result = await db.execute(
                select(ImageHistory).where(ImageHistory.user_id == int(request.user_id))
            )
            rows = result.scalars().all()

        items = [
            img_pb2.ImageHistoryItem(
                id=row.id,
                user_id=str(row.user_id),
                prompt=row.prompt,
                image_url=row.image_url or "",
                results_json=json.dumps(row.results) if isinstance(row.results, (list, dict)) else str(row.results),
                timestamp=str(row.timestamp),
            )
            for row in rows
        ]

        return img_pb2.ListHistoryResponse(items=items, total=len(items))

    # --------------------------
    # RPC: DeleteImage
    # --------------------------
    async def DeleteImage(self, request: img_pb2.DeleteImageRequest, context: aio.ServicerContext) -> img_pb2.DeleteImageResponse:
        LOG.info("DeleteImage called id=%s user_id=%s", request.id, request.user_id)

        # verify token
        token = extract_bearer_from_metadata(context)
        user_payload = await self._verify_token_with_authsvc(token)
        if user_payload is None:
            context.abort(grpc.StatusCode.UNAUTHENTICATED, "Invalid or missing token")

        async with async_session_maker() as db:
            item = await db.get(ImageHistory, request.id)
            if not item or item.user_id != int(request.user_id):
                context.abort(grpc.StatusCode.NOT_FOUND, "Item not found or not owned by user")
            try:
                await db.delete(item)
                await db.commit()
                LOG.info("Deleted image history id=%s", request.id)
            except Exception as e:
                await db.rollback()
                LOG.error("DB delete error: %s", e, exc_info=True)
                context.abort(grpc.StatusCode.INTERNAL, f"DB delete error: {e}")

        return img_pb2.DeleteImageResponse(ok=True, error="")


# --------------------------
# gRPC server entrypoint
# --------------------------
async def serve(host="0.0.0.0", port=50057):
    server = aio.server()
    img_grpc.add_ImageServiceServicer_to_server(ImageService(), server)
    listen_addr = f"{host}:{port}"
    server.add_insecure_port(listen_addr)
    LOG.info("🚀 Starting ImageService gRPC server on %s", listen_addr)
    await server.start()
    await server.wait_for_termination()


if __name__ == "__main__":
    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        LOG.info("Server stopped by user")
