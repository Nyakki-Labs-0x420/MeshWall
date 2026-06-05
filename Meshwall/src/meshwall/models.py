from sqlalchemy import Column, Integer, String, Float, Text, DateTime, func
from sqlalchemy.ext.declarative import declarative_base

Base = declarative_base()


class BlockedIP(Base):
    __tablename__ = "blocked_ip"
    id = Column(Integer, primary_key=True)
    ip = Column(String(45), unique=True, nullable=False, index=True)
    reason = Column(String(255))
    geo_country = Column(String(2))
    geo_city = Column(String(100))
    asn = Column(String(20))
    provider = Column(String(100))
    lat = Column(Float)
    lng = Column(Float)
    traceroute = Column(Text)          
    blocked_at = Column(DateTime, server_default=func.now())


class BlockedDomain(Base):
    __tablename__ = "blocked_domain"
    id = Column(Integer, primary_key=True)
    domain = Column(String(255), unique=True, nullable=False, index=True)
    reason = Column(String(255))
    blocked_at = Column(DateTime, server_default=func.now())


class ChatMessage(Base):
    __tablename__ = "chat_message"
    id = Column(Integer, primary_key=True)
    role = Column(String(20))           
    content_encrypted = Column(Text)     
    created_at = Column(DateTime, server_default=func.now())


class FeedBlock(Base):
    """Stores IPs loaded from threat feeds (mass blocklists)."""
    __tablename__ = "feed_block"
    id = Column(Integer, primary_key=True)
    ip = Column(String(45), unique=True, nullable=False, index=True)
    source = Column(String(255))         
    added_at = Column(DateTime, server_default=func.now())