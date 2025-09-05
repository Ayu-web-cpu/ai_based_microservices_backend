import os
import logging
import httpx
from dotenv import load_dotenv
from typing import List, Optional

from fastapi import FastAPI, Depends, HTTPException, Security
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel

# ============================================================
# ENV + CONFIG
# ============================================================
load_dotenv()

AUTH_SERVICE_URL = os.getenv("AUTH_SERVICE_URL", "http://localhost:8000/auth")
IMAGE_SERVICE_URL = os.getenv("IMAGE_SERVICE_URL", "http://localhost:8002/image")
SEARCH_SERVICE_URL = os.getenv("SEARCH_SERVICE_URL", "http://localhost:8003/search")

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


# ============================================================
# FASTAPI APP
# ============================================================
app = FastAPI(title="API Gateway", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ============================================================
# AUTH HANDLER (ONLY EXTRACT TOKEN, NO VERIFY)
# ============================================================
security = HTTPBearer()

class CurrentUser(BaseModel):
    token: str

async def get_current_user(credentials: HTTPAuthorizationCredentials = Security(security)):
    if not credentials:
        raise HTTPException(status_code=401, detail="Missing Authorization header")
    return CurrentUser(token=credentials.credentials)

# ============================================================
# REQUEST + RESPONSE MODELS
# ============================================================
# Auth
class AuthRequest(BaseModel):
    email: str
    password: str

class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

# Image
class ImageGenerateRequest(BaseModel):
    prompt: str

class ImageGenerateResponse(BaseModel):
    id: int
    prompt: str
    image_url: Optional[str]
    timestamp: str
    user_id: int

class ImageHistoryItem(BaseModel):
    id: int
    prompt: str
    image_url: Optional[str]
    timestamp: str
    user_id: int

class ImageHistoryResponse(BaseModel):
    history: List[ImageHistoryItem]

class DeleteResponse(BaseModel):
    message: str

# Search
class SearchRequest(BaseModel):
    query: str

class SearchResult(BaseModel):
    id: int
    query: str
    results: List[str]
    timestamp: str
    user_id: int

class SearchHistoryItem(BaseModel):
    id: int
    query: str
    results: List[str]
    meta: Optional[dict]
    timestamp: str
    user_id: int

class SearchHistoryResponse(BaseModel):
    history: List[SearchHistoryItem]

# ============================================================
# FORWARD HELPER
# ============================================================
async def forward_request(url: str, method: str, headers: dict = None, data: dict = None, params: dict = None):
    async with httpx.AsyncClient() as client:
        try:
            if method == "GET":
                resp = await client.get(url, headers=headers, params=params)
            elif method == "POST":
                resp = await client.post(url, headers=headers, json=data)
            elif method == "PUT":
                resp = await client.put(url, headers=headers, json=data)
            elif method == "DELETE":
                resp = await client.delete(url, headers=headers)
            else:
                raise HTTPException(status_code=405, detail="Method not allowed")

            resp.raise_for_status()
            return resp.json()
        except httpx.HTTPStatusError as e:
            logger.error(f"HTTP error forwarding to {url}: {str(e)}")
            raise HTTPException(status_code=e.response.status_code, detail=e.response.text)
        except Exception as e:
            logger.error(f"Error forwarding to {url}: {str(e)}")
            raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

# ============================================================
# AUTH SERVICE (8000)
# ============================================================
@app.post("/auth/register", response_model=TokenResponse)
async def register(data: AuthRequest):
    return await forward_request(f"{AUTH_SERVICE_URL}/register", "POST", data=data.dict())

@app.post("/auth/login", response_model=TokenResponse)
async def login(data: AuthRequest):
    return await forward_request(f"{AUTH_SERVICE_URL}/login", "POST", data=data.dict())

@app.post("/auth/refresh", response_model=TokenResponse)
async def refresh(data: dict):
    return await forward_request(f"{AUTH_SERVICE_URL}/refresh", "POST", data=data)

# ============================================================
# IMAGE SERVICE (8002)
# ============================================================
@app.post("/image/generate", response_model=ImageGenerateResponse)
async def generate_image(data: ImageGenerateRequest, user: CurrentUser = Depends(get_current_user)):
    headers = {"Authorization": f"Bearer {user.token}"}   # ✅ forward unchanged
    return await forward_request(f"{IMAGE_SERVICE_URL}/", "POST", headers=headers, data=data.dict())

@app.get("/image/history", response_model=ImageHistoryResponse)
async def image_history(user: CurrentUser = Depends(get_current_user)):
    headers = {"Authorization": f"Bearer {user.token}"}   # ✅ forward unchanged
    return await forward_request(f"{IMAGE_SERVICE_URL}/history", "GET", headers=headers)

@app.delete("/image/{item_id}", response_model=DeleteResponse)
async def delete_image(item_id: int, user: CurrentUser = Depends(get_current_user)):
    headers = {"Authorization": f"Bearer {user.token}"}   # ✅ forward unchanged
    return await forward_request(f"{IMAGE_SERVICE_URL}/{item_id}", "DELETE", headers=headers)

# ============================================================
# SEARCH SERVICE (8003)
# ============================================================
@app.post("/search/query", response_model=SearchResult)
async def search_query(data: SearchRequest, user: CurrentUser = Depends(get_current_user)):
    headers = {"Authorization": f"Bearer {user.token}"}   # ✅ forward unchanged
    return await forward_request(f"{SEARCH_SERVICE_URL}/", "POST", headers=headers, data=data.dict())

@app.get("/search/history", response_model=SearchHistoryResponse)
async def search_history(user: CurrentUser = Depends(get_current_user)):
    headers = {"Authorization": f"Bearer {user.token}"}   # ✅ forward unchanged
    return await forward_request(f"{SEARCH_SERVICE_URL}/history", "GET", headers=headers)

@app.delete("/search/{item_id}", response_model=DeleteResponse)
async def delete_search(item_id: int, user: CurrentUser = Depends(get_current_user)):
    headers = {"Authorization": f"Bearer {user.token}"}   # ✅ forward unchanged
    return await forward_request(f"{SEARCH_SERVICE_URL}/{item_id}", "DELETE", headers=headers)