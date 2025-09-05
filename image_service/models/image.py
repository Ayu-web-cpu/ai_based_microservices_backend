from sqlalchemy import Column, Integer, String, DateTime, Text, JSON
from sqlalchemy.sql import func

from models.base import Base

class ImageHistory(Base):
    __tablename__ = "image_history"   # 👈 fixed typo (was "immage_history")

    id = Column(Integer, primary_key=True, index=True)
    prompt = Column(String, nullable=False)       # the text prompt used to generate image
    results = Column(JSON, nullable=True)         # raw outputs (JSON format)
    image_url = Column(String, nullable=True)     # generated image URL if available
    meta = Column(Text, nullable=True)            # optional extra info
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    # Store only user_id, no direct relationship with Auth Service
    user_id = Column(Integer, nullable=False)

