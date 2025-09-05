import sys, os
# 👇 Add project root (parent of search_service/) to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from fastapi import FastAPI
from models.base import Base
from db.session import engine
from routers import search


app = FastAPI(
    title="Search Service",
    description="Handles search queries and history",
    version="1.0.0"
)

# ✅ Include routers
app.include_router(search.search_router)   # login routes
app.include_router(search.router)          # protected routes

# ✅ Startup event → create DB tables
@app.on_event("startup")
async def on_startup():
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

# ✅ Health check endpoint
@app.get("/")
def root():
    return {"message": "Search Service is running"}
