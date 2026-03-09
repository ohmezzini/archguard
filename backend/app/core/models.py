from __future__ import annotations
from typing import Optional
from datetime import datetime
from sqlmodel import SQLModel, Field, Column, JSON

class Service(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    owner_team: str = "unknown"
    domain: str = "unknown"
    environment: str = "prod"
    platform: str = "EKS"
    criticality: str = "high"
    data_classification: str = "confidential"
    exposure: str = "internal"
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class BlueprintVersion(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    service_id: int = Field(foreign_key="service.id", index=True)
    version: int = Field(index=True)
    blueprint_json: dict = Field(sa_column=Column(JSON), default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: str = "system"

class Evaluation(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    service_id: int = Field(foreign_key="service.id", index=True)
    blueprint_id: int = Field(foreign_key="blueprintversion.id", index=True)
    ruleset_version: str = "mvp-0.1"
    traffic_light: str = "unknown"
    score_json: dict = Field(sa_column=Column(JSON), default_factory=dict)
    blockers_json: list = Field(sa_column=Column(JSON), default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)

class Finding(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    evaluation_id: int = Field(foreign_key="evaluation.id", index=True)
    rule_id: str
    dimension: str
    severity: str
    title: str
    description: str
    recommendation: str
    is_blocker: bool = False
    evidence_required: list = Field(sa_column=Column(JSON), default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)

class InterviewSession(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    service_id: int = Field(foreign_key="service.id", index=True)
    blueprint_id: int = Field(foreign_key="blueprintversion.id", index=True)
    status: str = "active"
    question_budget_total: int = 12
    question_budget_remaining: int = 12
    asked_question_ids: list = Field(sa_column=Column(JSON), default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)

class InterviewTurn(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    session_id: int = Field(foreign_key="interviewsession.id", index=True)
    turn_index: int = Field(index=True)
    user_message: str
    assistant_message: str
    state_update_json: dict = Field(sa_column=Column(JSON), default_factory=dict)
    asked_question_ids: list = Field(sa_column=Column(JSON), default_factory=list)
    next_questions: list = Field(sa_column=Column(JSON), default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ExternalSource(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    name: str
    kind: str
    auth_type: str = "none"
    base_url: Optional[str] = None
    is_enabled: bool = True
    last_sync_at: Optional[datetime] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class ExternalAsset(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    source_id: int = Field(foreign_key="externalsource.id", index=True)
    external_id: str = Field(index=True)
    asset_type: str
    name: str
    account_id: Optional[str] = None
    region: Optional[str] = None
    service_name_guess: Optional[str] = None
    correlated_service_id: Optional[int] = Field(default=None, foreign_key="service.id", index=True)
    correlation_confidence: Optional[float] = None
    raw_json: dict = Field(sa_column=Column(JSON), default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class ExternalFinding(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    source_id: int = Field(foreign_key="externalsource.id", index=True)
    asset_id: Optional[int] = Field(default=None, foreign_key="externalasset.id", index=True)
    external_finding_id: str = Field(index=True)
    title: str
    description: str = ""
    severity: str = "medium"
    status: str = "open"
    compliance_status: Optional[str] = None
    resource_id: Optional[str] = None
    resource_type: Optional[str] = None
    provider: Optional[str] = None
    first_seen_at: Optional[datetime] = None
    last_seen_at: Optional[datetime] = None
    correlated_service_id: Optional[int] = Field(default=None, foreign_key="service.id", index=True)
    correlation_confidence: Optional[float] = None
    raw_json: dict = Field(sa_column=Column(JSON), default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)


class ExternalTicket(SQLModel, table=True):
    id: Optional[int] = Field(default=None, primary_key=True)
    source_id: int = Field(foreign_key="externalsource.id", index=True)
    external_ticket_id: str = Field(index=True)
    ticket_key: str = Field(index=True)
    title: str
    status: str = "open"
    priority: Optional[str] = None
    assignee: Optional[str] = None
    project: Optional[str] = None
    due_date: Optional[str] = None
    labels_json: list = Field(sa_column=Column(JSON), default_factory=list)
    linked_asset_id: Optional[int] = Field(default=None, foreign_key="externalasset.id", index=True)
    linked_finding_id: Optional[int] = Field(default=None, foreign_key="externalfinding.id", index=True)
    correlated_service_id: Optional[int] = Field(default=None, foreign_key="service.id", index=True)
    correlation_confidence: Optional[float] = None
    raw_json: dict = Field(sa_column=Column(JSON), default_factory=dict)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
