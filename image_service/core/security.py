from fastapi import Depends, HTTPException
from fastapi.security import OAuth2PasswordBearer
import httpx

# 👇 Dummy tokenUrl just for Swagger docs
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

AUTH_VERIFY_URL = "http://localhost:8001/auth/verify"

async def verify_user(token: str = Depends(oauth2_scheme)):
    async with httpx.AsyncClient() as client:
        response = await client.post(AUTH_VERIFY_URL, json={"token": token})
        if response.status_code != 200:
            raise HTTPException(status_code=401, detail="Invalid or expired token")
        return response.json()  # { "sub": user_id, "role": role }
