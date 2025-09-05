# test_search_server.py
import asyncio, grpc
import search_pb2 as pb
import search_pb2_grpc as pb_grpc

async def main():
    addr = "localhost:50055"
    async with grpc.aio.insecure_channel(addr) as ch:
        stub = pb_grpc.GatewayAuthSearchStub(ch)
        try:
            # try a Verify call with a bogus token to check method existence
            resp = await stub.Verify(pb.VerifyRequest(token="x"), timeout=3.0)
            print("Verify response:", resp)
        except grpc.aio.AioRpcError as e:
            print("gRPC error:", e.code(), e.details())

if __name__ == "__main__":
    asyncio.run(main())
