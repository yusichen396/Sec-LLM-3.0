"""SQLAlchemy ORM models for Sec-LLM Agent Platform."""
from datetime import datetime, timezone

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text, create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from config import settings


class Base(DeclarativeBase):
    pass


# ---- Existing tables mapped to ORM ----

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, autoincrement=True)
    username = Column(String(50), unique=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    email = Column(String(100), unique=True, nullable=True)
    full_name = Column(String(100), nullable=True)
    role = Column(String(20), default="user")
    llm_provider = Column(String(20), default="local")
    is_active = Column(Boolean, default=False)
    verification_token = Column(String(255), nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_login = Column(DateTime, nullable=True)


class LogRecord(Base):
    __tablename__ = "log_records"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    filename = Column(String(255), nullable=True)
    upload_time = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    threat_level = Column(String(50), nullable=True)
    attack_type = Column(String(100), nullable=True)
    source_ip = Column(String(50), nullable=True)
    summary = Column(Text, nullable=True)
    status = Column(String(20), default="unresolved")


class ChatHistory(Base):
    __tablename__ = "chat_histories"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=False)
    title = Column(String(32), nullable=False)
    messages = Column(JSON, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


class KnowledgeFile(Base):
    __tablename__ = "knowledge_files"
    id = Column(Integer, primary_key=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    filename = Column(String(255), nullable=False)
    upload_time = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    file_size = Column(Integer, nullable=True)
    chunk_count = Column(Integer, nullable=True)
    status = Column(String(20), default="indexed")


# ---- NEW: Agent-specific tables ----

class AgentSession(Base):
    __tablename__ = "agent_sessions"
    id = Column(String(8), primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"), nullable=True)
    target = Column(String(500), nullable=False)
    task_type = Column(String(50), default="web_scan")
    provider = Column(String(20), default="local")
    status = Column(String(20), default="running")
    phase = Column(String(50), nullable=True)
    findings_count = Column(Integer, default=0)
    steps_completed = Column(Integer, default=0)
    steps_total = Column(Integer, default=0)
    report = Column(Text, nullable=True)
    logs = Column(JSON, default=list)
    findings = Column(JSON, default=list)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))


# ---- Engine factory ----

def get_engine():
    db_url = (
        f"mysql+pymysql://{settings.MYSQL_USER}:{settings.MYSQL_PASSWORD}"
        f"@{settings.MYSQL_HOST}:{settings.MYSQL_PORT}/{settings.MYSQL_DB}"
        f"?charset=utf8mb4"
    )
    return create_engine(db_url, pool_size=10, max_overflow=20, pool_pre_ping=True)


def get_session_factory():
    return sessionmaker(bind=get_engine(), expire_on_commit=False)
