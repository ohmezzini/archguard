from __future__ import annotations

import datetime
from typing import Any, Dict, List
from sqlmodel import select

from app.core.db import get_session
from app.core.models import Service, BlueprintVersion, Evaluation, Finding
from app.core.schema import Blueprint
from app.core.rules_engine import evaluate as evaluate_rules


def _mk_blueprint(patch: Dict[str, Any]) -> Dict[str, Any]:
    bp = Blueprint().model_dump()

    def deep_merge(dst, p):
        for k, v in p.items():
            if isinstance(v, dict) and isinstance(dst.get(k), dict):
                deep_merge(dst[k], v)
            else:
                dst[k] = v
        return dst

    return deep_merge(bp, patch)


def _latest_blueprint(session, service_id: int) -> BlueprintVersion | None:
    stmt = (
        select(BlueprintVersion)
        .where(BlueprintVersion.service_id == service_id)
        .order_by(BlueprintVersion.version.desc())
        .limit(1)
    )
    return session.exec(stmt).first()


def _create_blueprint(session, service: Service, blueprint_json: dict, created_by: str) -> BlueprintVersion:
    latest = _latest_blueprint(session, service.id)
    next_version = 1 if not latest else latest.version + 1
    bpv = BlueprintVersion(
        service_id=service.id,
        version=next_version,
        blueprint_json=blueprint_json,
        created_by=created_by,
    )
    session.add(bpv)
    session.commit()
    session.refresh(bpv)
    return bpv


def _persist_evaluation(
    session,
    service: Service,
    bpv: BlueprintVersion,
    rules: List[Dict[str, Any]],
    ruleset_version: str,
) -> Evaluation:
    service_ctx = {
        "exposure": service.exposure,
        "platform": service.platform,
        "environment": service.environment,
        "criticality": service.criticality,
        "data_classification": service.data_classification,
    }
    result = evaluate_rules(service_ctx, bpv.blueprint_json, rules)

    ev = Evaluation(
        service_id=service.id,
        blueprint_id=bpv.id,
        ruleset_version=ruleset_version,
        traffic_light=result["score"]["traffic_light"],
        score_json=result["score"],
        blockers_json=result["blockers"],
        created_at=datetime.datetime.utcnow(),
    )
    session.add(ev)
    session.commit()
    session.refresh(ev)

    for f in result["findings"]:
        session.add(
            Finding(
                evaluation_id=ev.id,
                rule_id=f["rule_id"],
                dimension=f["dimension"],
                severity=f["severity"],
                title=f["title"],
                description=f["description"],
                recommendation=f["recommendation"],
                is_blocker=f["is_blocker"],
                evidence_required=f.get("evidence_required", []),
                created_at=datetime.datetime.utcnow(),
            )
        )
    session.commit()
    return ev


def seed_if_empty(rules: List[Dict[str, Any]], ruleset_version: str, force: bool = False) -> Dict[str, Any]:
    """Seed pack (CTO/CISO demo): 5 services across EKS/ECS + exposure levels.

    - Includes "good" and "bad" archetypes aligned to practical cyber governance outcomes
      (e.g., controls around IAM, encryption, logging/retention, supply chain, and egress restriction).
    - Idempotent unless force=True.
    """
    with get_session() as session:
        existing = session.exec(select(Service)).first()
        if existing and not force:
            return {"seeded": False, "reason": "services already exist"}

        if force:
            for tbl in [Finding, Evaluation, BlueprintVersion, Service]:
                rows = session.exec(select(tbl)).all()
                for r in rows:
                    session.delete(r)
            session.commit()

        demos = [
            # 1) BAD - Public payments API (designed to show RED + blockers)
            {
                "svc": dict(
                    name="payments-api (BAD/public)",
                    owner_team="FinOps",
                    domain="Payments",
                    environment="prod",
                    platform="EKS",
                    criticality="high",
                    data_classification="restricted",
                    exposure="public",
                ),
                "bp_patch": {
                    "ingress": {"type": "ALB", "auth": "none", "waf": "no", "rate_limit": "no"},
                    "network": {"subnets": "public", "egress": {"internet": "yes", "restricted": "no", "allowed_domains": []}},
                    "identity": {"workload_identity": "IRSA", "iam_least_privilege": "unknown", "rbac": "unknown"},
                    "secrets": {"backend": "SecretsManager", "rotation": "manual"},
                    "data": {"sensitive": "yes", "encryption_at_rest": "no", "encryption_in_transit": "yes", "logs_may_contain_pii": "yes", "redaction": "no"},
                    "supply_chain": {"sbom": "unknown", "image_signing": "unknown", "container_scan": "no"},
                    "cicd": {"gates": {"sast": "unknown", "sca": "no", "secrets_scan": "unknown", "iac_scan": "unknown", "policy_as_code": "unknown"}},
                    "observability": {"central_logging": "unknown", "siem": "unknown", "retention_days": "unknown"},
                },
            },
            # 2) GOOD - Public edge gateway (EKS) showing GREEN posture
            {
                "svc": dict(
                    name="mobile-edge-gateway (GOOD/public)",
                    owner_team="Platform",
                    domain="Edge",
                    environment="prod",
                    platform="EKS",
                    criticality="high",
                    data_classification="confidential",
                    exposure="public",
                ),
                "bp_patch": {
                    "ingress": {"type": "APIGW", "auth": "OIDC", "waf": "yes", "rate_limit": "yes"},
                    "network": {"subnets": "private", "egress": {"internet": "yes", "restricted": "yes", "allowed_domains": ["idp.example.com", "api.partner.com"]}},
                    "identity": {"workload_identity": "IRSA", "iam_least_privilege": "yes", "rbac": "yes"},
                    "secrets": {"backend": "SecretsManager", "rotation": "auto"},
                    "data": {"sensitive": "yes", "encryption_at_rest": "yes", "encryption_in_transit": "yes", "logs_may_contain_pii": "yes", "redaction": "yes"},
                    "supply_chain": {"sbom": "yes", "image_signing": "yes", "container_scan": "yes"},
                    "cicd": {"gates": {"sast": "yes", "sca": "yes", "secrets_scan": "yes", "iac_scan": "yes", "policy_as_code": "yes"}},
                    "observability": {"central_logging": "yes", "siem": "yes", "retention_days": 180},
                },
            },
            # 3) GOOD-ish - Internal ECS worker (high data sensitivity, strong encryption/logging)
            {
                "svc": dict(
                    name="kyc-worker (GOOD/internal)",
                    owner_team="Risk",
                    domain="Onboarding",
                    environment="prod",
                    platform="ECS",
                    criticality="high",
                    data_classification="restricted",
                    exposure="internal",
                ),
                "bp_patch": {
                    "ingress": {"type": "None"},
                    "network": {"subnets": "private", "egress": {"internet": "no", "restricted": "yes", "allowed_domains": []}},
                    "identity": {"workload_identity": "TaskRole", "iam_least_privilege": "yes", "rbac": "yes"},
                    "secrets": {"backend": "SSM", "rotation": "auto"},
                    "data": {"sensitive": "yes", "encryption_at_rest": "yes", "encryption_in_transit": "yes", "logs_may_contain_pii": "yes", "redaction": "yes"},
                    "supply_chain": {"sbom": "yes", "image_signing": "yes", "container_scan": "yes"},
                    "cicd": {"gates": {"sast": "yes", "sca": "yes", "secrets_scan": "yes", "iac_scan": "yes", "policy_as_code": "unknown"}},
                    "observability": {"central_logging": "yes", "siem": "yes", "retention_days": 365},
                },
            },
            # 4) MIXED - Partner notifications (stg, good edge, but SIEM/retention unknown => yellow-ish)
            {
                "svc": dict(
                    name="notifications (MIXED/partner)",
                    owner_team="Product",
                    domain="Messaging",
                    environment="stg",
                    platform="EKS",
                    criticality="medium",
                    data_classification="confidential",
                    exposure="partner",
                ),
                "bp_patch": {
                    "ingress": {"type": "APIGW", "auth": "JWT", "waf": "yes", "rate_limit": "yes"},
                    "network": {"subnets": "private", "egress": {"internet": "yes", "restricted": "yes", "allowed_domains": ["smtp.relay.local"]}},
                    "identity": {"workload_identity": "IRSA", "iam_least_privilege": "yes", "rbac": "unknown"},
                    "secrets": {"backend": "Vault", "rotation": "auto"},
                    "data": {"sensitive": "no", "encryption_at_rest": "yes", "encryption_in_transit": "yes", "logs_may_contain_pii": "unknown", "redaction": "unknown"},
                    "supply_chain": {"sbom": "unknown", "image_signing": "unknown", "container_scan": "yes"},
                    "cicd": {"gates": {"sast": "yes", "sca": "yes", "secrets_scan": "yes", "iac_scan": "unknown", "policy_as_code": "unknown"}},
                    "observability": {"central_logging": "yes", "siem": "unknown", "retention_days": "unknown"},
                },
            },
            # 5) BAD - Audit log pipeline with StaticKeys to show IAM blocker
            {
                "svc": dict(
                    name="audit-log (BAD/internal)",
                    owner_team="SecOps",
                    domain="Security",
                    environment="prod",
                    platform="EKS",
                    criticality="high",
                    data_classification="confidential",
                    exposure="internal",
                ),
                "bp_patch": {
                    "ingress": {"type": "None"},
                    "network": {"subnets": "private", "egress": {"internet": "yes", "restricted": "no", "allowed_domains": []}},
                    "identity": {"workload_identity": "StaticKeys", "iam_least_privilege": "unknown", "rbac": "unknown"},
                    "secrets": {"backend": "EnvVar", "rotation": "none"},
                    "data": {"sensitive": "yes", "encryption_at_rest": "yes", "encryption_in_transit": "yes", "logs_may_contain_pii": "yes", "redaction": "unknown"},
                    "supply_chain": {"sbom": "unknown", "image_signing": "unknown", "container_scan": "unknown"},
                    "cicd": {"gates": {"sast": "unknown", "sca": "unknown", "secrets_scan": "unknown", "iac_scan": "unknown", "policy_as_code": "unknown"}},
                    "observability": {"central_logging": "yes", "siem": "yes", "retention_days": "unknown"},
                },
            },
        ]

        created_ids = []
        for d in demos:
            svc = Service(**d["svc"], updated_at=datetime.datetime.utcnow())
            session.add(svc)
            session.commit()
            session.refresh(svc)

            bp = _mk_blueprint(d["bp_patch"])
            bpv = _create_blueprint(session, svc, bp, created_by="seed_pack_bcb85_cmn4893")
            _persist_evaluation(session, svc, bpv, rules, ruleset_version)

            created_ids.append(svc.id)

        return {"seeded": True, "services_created": len(created_ids), "service_ids": created_ids}
