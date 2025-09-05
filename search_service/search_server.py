# search_server.py
# search_server.py
import os
import sys
import asyncio
import logging
import json
from typing import List

# Make project root importable (adjust if you run differently)
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import grpc
from grpc import aio
from sqlalchemy import select

# generated protos (from your search.proto)
import search_pb2 as pb
import search_pb2_grpc as pb_grpc

# project imports
from core import security
from db.session import async_session_maker   # should give AsyncSession via context manager
from models.search import SearchHistory

LOG = logging.getLogger("search_server")
logging.basicConfig(level=logging.INFO)


class GatewayAuthSearchServicer(pb_grpc.GatewayAuthSearchServicer):
    # NOTE: Login is intentionally NOT implemented here because the auth service owns user auth.
    # If you still want Login here, you must provide models.user and user table access.

    async def Verify(self, request: pb.VerifyRequest, context) -> pb.VerifyResponse:
        token = request.token or ""
        if not token:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "token required")

        try:
            payload = security.decode_token(token)
            sub = str(payload.get("sub", "")) if isinstance(payload, dict) else ""
            role = payload.get("role", "") if isinstance(payload, dict) else ""
            return pb.VerifyResponse(sub=sub, role=role, valid=True, error="")
        except Exception as e:
            return pb.VerifyResponse(sub="", role="", valid=False, error=str(e))

    # ----------------------------
    # Search history RPCs
    # ----------------------------
    async def SaveHistory(self, request: pb.SaveHistoryRequest, context) -> pb.SaveHistoryResponse:
        user_id = (request.user_id or "").strip()
        query = (request.query or "").strip()

        if not user_id or not query:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "user_id and query required")

        results_py = []
        for r in request.results:
            results_py.append({"text": getattr(r, "text", ""), "url": getattr(r, "url", "")})

        try:
            async with async_session_maker() as db:
                new = SearchHistory(
                    query=query,
                    results=json.dumps(results_py),
                    meta=None,
                    user_id=int(user_id)
                )
                db.add(new)
                await db.commit()
                await db.refresh(new)
                return pb.SaveHistoryResponse(ok=True, id=new.id, error="")
        except Exception as e:
            LOG.exception("SaveHistory failed")
            await context.abort(grpc.StatusCode.INTERNAL, f"save failed: {e}")

    async def ListHistory(self, request: pb.ListHistoryRequest, context) -> pb.ListHistoryResponse:
        user_id = (request.user_id or "").strip()
        limit = int(request.limit) if request.limit else 50
        offset = int(request.offset) if request.offset else 0

        if not user_id:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "user_id required")

        try:
            async with async_session_maker() as db:
                q = await db.execute(
                    select(SearchHistory)
                    .where(SearchHistory.user_id == int(user_id))
                    .order_by(SearchHistory.timestamp.desc())
                    .limit(limit)
                    .offset(offset)
                )
                items = q.scalars().all()

                resp_items = []
                for it in items:
                    try:
                        parsed_results = json.loads(it.results) if isinstance(it.results, str) else it.results
                    except Exception:
                        parsed_results = it.results or []

                    pb_results = []
                    for r in parsed_results:
                        text = r.get("text") if isinstance(r, dict) else str(r)
                        url = r.get("url", "") if isinstance(r, dict) else ""
                        pb_results.append(pb.SearchResult(text=text, url=url))

                    resp_items.append(
                        pb.HistoryItem(
                            id=int(it.id),
                            user_id=str(it.user_id),
                            query=str(it.query),
                            results=pb_results,
                            timestamp=str(it.timestamp),
                        )
                    )

                return pb.ListHistoryResponse(items=resp_items, total=len(resp_items))

        except Exception as e:
            LOG.exception("ListHistory failed")
            await context.abort(grpc.StatusCode.INTERNAL, f"list failed: {e}")

    async def DeleteHistory(self, request: pb.DeleteHistoryRequest, context) -> pb.DeleteHistoryResponse:
        item_id = int(request.id) if request.id else 0
        user_id = (request.user_id or "").strip()

        if not item_id or not user_id:
            await context.abort(grpc.StatusCode.INVALID_ARGUMENT, "id and user_id required")

        try:
            async with async_session_maker() as db:
                item = await db.get(SearchHistory, item_id)
                if not item:
                    return pb.DeleteHistoryResponse(ok=False, error="item not found")
                if str(item.user_id) != str(int(user_id)):
                    return pb.DeleteHistoryResponse(ok=False, error="not owner")

                await db.delete(item)
                await db.commit()
                return pb.DeleteHistoryResponse(ok=True, error="")
        except Exception as e:
            LOG.exception("DeleteHistory failed")
            await context.abort(grpc.StatusCode.INTERNAL, f"delete failed: {e}")


async def serve(host: str = "0.0.0.0", port: int = 50051):
    server = aio.server()
    pb_grpc.add_GatewayAuthSearchServicer_to_server(GatewayAuthSearchServicer(), server)

    bind_addr = f"{host}:{port}"
    server.add_insecure_port(bind_addr)
    LOG.info("Starting gRPC server on %s", bind_addr)
    await server.start()
    await server.wait_for_termination()


if __name__ == "__main__":
    host = os.environ.get("AUTH_GRPC_HOST", "0.0.0.0")
    port = int(os.environ.get("AUTH_GRPC_PORT", "50055"))
    try:
        asyncio.run(serve(host=host, port=port))
    except KeyboardInterrupt:
        LOG.info("Shutting down")
