"""
AstraSOC - Database Layer
SQLAlchemy ORM models and session management.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime
from typing import Generator

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Integer,
    JSON,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session, relationship, sessionmaker

from backend.core.config import settings

# ── Engine & Session ──────────────────────────────────────────────────────────

engine = create_engine(
    settings.database_url,
    connect_args={"check_same_thread": False} if "sqlite" in settings.database_url else {},
    echo=settings.debug,
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that yields a database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Base ──────────────────────────────────────────────────────────────────────

class Base(DeclarativeBase):
    pass


# ── Enums ─────────────────────────────────────────────────────────────────────

class SeverityLevel(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AlertStatus(str, enum.Enum):
    OPEN = "OPEN"
    INVESTIGATING = "INVESTIGATING"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class UserRole(str, enum.Enum):
    ADMIN = "ADMIN"
    ANALYST = "ANALYST"
    VIEWER = "VIEWER"


# ── Models ────────────────────────────────────────────────────────────────────

class User(Base):
    __tablename__ = "users"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(256), unique=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    role = Column(Enum(UserRole), default=UserRole.ANALYST)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)


class RawLog(Base):
    __tablename__ = "raw_logs"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, nullable=False, index=True)
    source_ip = Column(String(45), nullable=True, index=True)
    destination_ip = Column(String(45), nullable=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)
    protocol = Column(String(16), nullable=True)
    event_type = Column(String(64), nullable=False, index=True)
    log_source = Column(String(64), nullable=False)   # auth | dns | network | firewall
    raw_data = Column(JSON, nullable=False)
    ingested_at = Column(DateTime, default=datetime.utcnow)


class Alert(Base):
    __tablename__ = "alerts"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    rule_id = Column(String(64), nullable=False)
    alert_type = Column(String(64), nullable=False, index=True)
    severity = Column(Enum(SeverityLevel), nullable=False, index=True)
    status = Column(Enum(AlertStatus), default=AlertStatus.OPEN, index=True)
    source_ip = Column(String(45), nullable=True, index=True)
    destination_ip = Column(String(45), nullable=True)
    description = Column(Text, nullable=False)
    raw_log_ids = Column(JSON, default=list)          # list of RawLog IDs
    mitre_tactics = Column(JSON, default=list)        # e.g. ["TA0001","T1110"]
    confidence_score = Column(Float, default=1.0)
    detected_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    incident_id = Column(String, ForeignKey("incidents.id"), nullable=True)

    incident = relationship("Incident", back_populates="alerts")


class Incident(Base):
    __tablename__ = "incidents"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    title = Column(String(256), nullable=False)
    severity = Column(Enum(SeverityLevel), nullable=False, index=True)
    status = Column(Enum(AlertStatus), default=AlertStatus.OPEN)
    risk_score = Column(Float, default=0.0)
    attack_chain = Column(JSON, default=list)         # ordered list of alert types
    mitre_mapping = Column(JSON, default=dict)
    affected_ips = Column(JSON, default=list)
    ai_summary = Column(Text, nullable=True)
    ai_root_cause = Column(Text, nullable=True)
    ai_mitigation = Column(Text, nullable=True)
    ai_confidence = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow, index=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    resolved_at = Column(DateTime, nullable=True)
    assigned_to = Column(String, ForeignKey("users.id"), nullable=True)

    alerts = relationship("Alert", back_populates="incident")


class ThreatIntelEntry(Base):
    __tablename__ = "threat_intel"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    ioc_type = Column(String(32), nullable=False)     # ip | domain | hash
    ioc_value = Column(String(512), nullable=False, index=True)
    threat_type = Column(String(64), nullable=True)
    confidence = Column(Float, default=0.5)
    source = Column(String(128), nullable=True)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)
    tags = Column(JSON, default=list)


def init_db() -> None:
    """Create all tables. Called on application startup."""
    Base.metadata.create_all(bind=engine)
