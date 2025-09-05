
from fastapi import FastAPI
from models.base import Base
from db.session import engine
from routers import image
import sys, os



# ✅ Create FastAPI app
app = FastAPI(
    title="Image Service",
    description="Handles image generation and history",
    version="1.0.0"
)

# ✅ Include both open and protected routers
app.include_router(image.login_router)  # open route (login via Auth gRPC)
app.include_router(image.router)        # protected routes (history, delete, generate)

# ✅ Startup event → create DB tables
@app.on_event("startup")
async def on_startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

# ✅ Health check endpoint
@app.get("/")
def root():
    return {"message": "Image Service is running"}

