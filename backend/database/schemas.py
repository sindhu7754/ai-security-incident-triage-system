"""
AstraSOC - Pydantic Schemas
Request and response models for the REST API.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field, field_validator, IPvAnyAddress

from backend.database.models import AlertStatus, SeverityLevel, UserRole


# ── Base ──────────────────────────────────────────────────────────────────────

class ORMBase(BaseModel):
    model_config = {"from_attributes": True}


# ── Auth ──────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=64)
    email: str
    password: str = Field(..., min_length=8)
    role: UserRole = UserRole.ANALYST


class UserResponse(ORMBase):
    id: str
    username: str
    email: str
    role: UserRole
    is_active: bool
    created_at: datetime


# ── Logs ──────────────────────────────────────────────────────────────────────

class LogIngestionRequest(BaseModel):
    """Single log event ingestion payload."""
    timestamp: datetime
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = Field(None, ge=0, le=65535)
    destination_port: Optional[int] = Field(None, ge=0, le=65535)
    protocol: Optional[str] = None
    event_type: str
    log_source: str  # auth | dns | network | firewall
    data: Dict[str, Any] = Field(default_factory=dict)

    @field_validator("log_source")
    @classmethod
    def validate_log_source(cls, v: str) -> str:
        allowed = {"auth", "dns", "network", "firewall", "endpoint"}
        if v.lower() not in allowed:
            raise ValueError(f"log_source must be one of {allowed}")
        return v.lower()


class LogIngestionResponse(BaseModel):
    log_id: str
    status: str
    alerts_triggered: int
    message: str


class BatchIngestionResponse(BaseModel):
    total: int
    accepted: int
    rejected: int
    alerts_triggered: int
    errors: List[str] = []


# ── Alerts ────────────────────────────────────────────────────────────────────

class AlertResponse(ORMBase):
    id: str
    rule_id: str
    alert_type: str
    severity: SeverityLevel
    status: AlertStatus
    source_ip: Optional[str]
    destination_ip: Optional[str]
    description: str
    mitre_tactics: List[str]
    confidence_score: float
    detected_at: datetime
    incident_id: Optional[str]


class AlertUpdateRequest(BaseModel):
    status: AlertStatus
    notes: Optional[str] = None


class AlertListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[AlertResponse]


# ── Incidents ─────────────────────────────────────────────────────────────────

class IncidentResponse(ORMBase):
    id: str
    title: str
    severity: SeverityLevel
    status: AlertStatus
    risk_score: float
    attack_chain: List[str]
    mitre_mapping: Dict[str, Any]
    affected_ips: List[str]
    ai_summary: Optional[str]
    ai_root_cause: Optional[str]
    ai_mitigation: Optional[str]
    ai_confidence: float
    created_at: datetime
    updated_at: datetime


class IncidentListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    items: List[IncidentResponse]


# ── Threat Intel ──────────────────────────────────────────────────────────────

class ThreatIntelCreate(BaseModel):
    ioc_type: str  # ip | domain | hash
    ioc_value: str
    threat_type: Optional[str] = None
    confidence: float = Field(0.5, ge=0.0, le=1.0)
    source: Optional[str] = None
    tags: List[str] = []


class ThreatIntelResponse(ORMBase):
    id: str
    ioc_type: str
    ioc_value: str
    threat_type: Optional[str]
    confidence: float
    source: Optional[str]
    first_seen: datetime
    last_seen: datetime
    is_active: bool
    tags: List[str]


# ── Stats ─────────────────────────────────────────────────────────────────────

class SOCStatsResponse(BaseModel):
    total_alerts: int
    open_alerts: int
    critical_alerts: int
    high_alerts: int
    total_incidents: int
    open_incidents: int
    avg_risk_score: float
    top_attacker_ips: List[Dict[str, Any]]
    alerts_by_type: Dict[str, int]
    alerts_last_24h: int


# ── AI Investigation ──────────────────────────────────────────────────────────

class InvestigationRequest(BaseModel):
    incident_id: str
    force_refresh: bool = False


class InvestigationResponse(BaseModel):
    incident_id: str
    severity: str
    attack_type: str
    summary: str
    root_cause: str
    affected_assets: List[str]
    iocs: List[Dict[str, str]]
    mitre_techniques: List[str]
    mitigation_steps: List[str]
    confidence: float
    generated_at: datetime
