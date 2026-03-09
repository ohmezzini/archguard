
from __future__ import annotations
import datetime
from typing import Dict, Any, List
from sqlmodel import select
from app.core.models import Service, ExternalSource, ExternalAsset, ExternalFinding, ExternalTicket

def ensure_default_sources(session) -> None:
    defaults = [
        {"name": "AWS Security Hub", "kind": "securityhub", "auth_type": "iam_role"},
        {"name": "DefectDojo", "kind": "defectdojo", "auth_type": "bearer_token"},
        {"name": "Jira", "kind": "jira", "auth_type": "bearer_token"},
    ]
    for d in defaults:
        found = session.exec(select(ExternalSource).where(ExternalSource.kind == d["kind"])).first()
        if not found:
            session.add(ExternalSource(**d, is_enabled=True))
    session.commit()

def _severity_to_num(sev: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get((sev or "").lower(), 0)

def run_mock_securityhub_sync(session) -> Dict[str, Any]:
    ensure_default_sources(session)
    source = session.exec(select(ExternalSource).where(ExternalSource.kind == "securityhub")).first()
    services = list(session.exec(select(Service)).all())
    created_assets = 0
    created_findings = 0
    for svc in services:
        external_id = f"arn:aws:{'ecs' if svc.platform == 'ECS' else 'eks'}::demo:{svc.name}"
        asset = session.exec(select(ExternalAsset).where(ExternalAsset.external_id == external_id)).first()
        if not asset:
            asset = ExternalAsset(
                source_id=source.id,
                external_id=external_id,
                asset_type="workload",
                name=svc.name,
                account_id="123456789012",
                region="sa-east-1",
                service_name_guess=svc.name,
                correlated_service_id=svc.id,
                correlation_confidence=0.98,
                raw_json={"platform": svc.platform, "environment": svc.environment},
            )
            session.add(asset)
            session.commit()
            session.refresh(asset)
            created_assets += 1

        findings = []
        if svc.exposure == "public":
            findings.append({
                "external_finding_id": f"sh-{svc.id}-public-ingress",
                "title": "Public-facing workload requires stronger edge controls",
                "description": "Mock Security Hub finding for exposed service.",
                "severity": "high",
                "compliance_status": "FAILED",
                "resource_type": "AwsEcsService" if svc.platform == "ECS" else "AwsEksCluster",
                "provider": "Security Hub",
            })
        if svc.criticality == "high":
            findings.append({
                "external_finding_id": f"sh-{svc.id}-logging",
                "title": "Centralized monitoring should be validated for critical workload",
                "description": "Mock finding tied to monitoring expectations.",
                "severity": "medium",
                "compliance_status": "WARNING",
                "resource_type": "AwsCloudWatchLogGroup",
                "provider": "Security Hub",
            })

        for f in findings:
            exists = session.exec(select(ExternalFinding).where(ExternalFinding.external_finding_id == f["external_finding_id"])).first()
            if not exists:
                session.add(ExternalFinding(
                    source_id=source.id,
                    asset_id=asset.id,
                    external_finding_id=f["external_finding_id"],
                    title=f["title"],
                    description=f["description"],
                    severity=f["severity"],
                    status="open",
                    compliance_status=f["compliance_status"],
                    resource_id=asset.external_id,
                    resource_type=f["resource_type"],
                    provider=f["provider"],
                    first_seen_at=datetime.datetime.utcnow(),
                    last_seen_at=datetime.datetime.utcnow(),
                    correlated_service_id=svc.id,
                    correlation_confidence=0.95,
                    raw_json=f,
                ))
                created_findings += 1

    source.last_sync_at = datetime.datetime.utcnow()
    source.updated_at = datetime.datetime.utcnow()
    session.add(source)
    session.commit()
    return {"source": "securityhub", "assets_created": created_assets, "findings_created": created_findings}

def connector_dashboard(session) -> Dict[str, Any]:
    ensure_default_sources(session)
    sources = list(session.exec(select(ExternalSource)).all())
    assets = list(session.exec(select(ExternalAsset)).all())
    findings = list(session.exec(select(ExternalFinding)).all())
    tickets = list(session.exec(select(ExternalTicket)).all())
    by_source = {}
    for src in sources:
        by_source[src.kind] = {
            "name": src.name,
            "enabled": src.is_enabled,
            "last_sync_at": src.last_sync_at.isoformat() if src.last_sync_at else None,
            "assets": len([a for a in assets if a.source_id == src.id]),
            "findings": len([f for f in findings if f.source_id == src.id]),
            "tickets": len([t for t in tickets if t.source_id == src.id]),
        }
    top_services = {}
    for f in findings:
        sid = f.correlated_service_id
        if sid is None:
            continue
        top_services.setdefault(sid, {"critical":0,"high":0,"medium":0,"low":0,"total":0})
        sev = (f.severity or "medium").lower()
        if sev not in top_services[sid]:
            sev = "medium"
        top_services[sid][sev] += 1
        top_services[sid]["total"] += 1
    return {"sources": by_source, "assets_total": len(assets), "findings_total": len(findings), "tickets_total": len(tickets), "top_services": top_services}

def findings_for_service(session, service_id: int) -> List[Dict[str, Any]]:
    rows = list(session.exec(select(ExternalFinding).where(ExternalFinding.correlated_service_id == service_id)).all())
    rows = sorted(rows, key=lambda x: (_severity_to_num(x.severity), x.updated_at or x.created_at), reverse=True)
    return [{
        "id": r.id,
        "title": r.title,
        "severity": r.severity,
        "status": r.status,
        "provider": r.provider,
        "resource_type": r.resource_type,
        "compliance_status": r.compliance_status,
    } for r in rows]
