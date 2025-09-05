from sqlalchemy import Column, Integer, String, DateTime, Text, JSON
from sqlalchemy.sql import func
from models.base import Base

class SearchHistory(Base):
    __tablename__ = "search_history"

    id = Column(Integer, primary_key=True, index=True)
    query = Column(String, nullable=False)        # user ka search query
    results = Column(JSON, nullable=True)         # search results (JSON format)
    meta = Column(Text, nullable=True)            # extra info (filters, pagination etc.)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())

    # Store only user_id, no direct relationship with Auth Service
    user_id = Column(Integer, nullable=False)
