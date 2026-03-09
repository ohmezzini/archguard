from __future__ import annotations
from typing import Any, Dict, List
import yaml, datetime

def load_rules(path: str) -> List[Dict[str, Any]]:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or []

def safe_eval(expr: str, ctx: Dict[str, Any]) -> bool:
    return bool(eval(expr, {"__builtins__": {}}, ctx))

def evaluate(service_ctx: Dict[str, Any], blueprint: Dict[str, Any], rules: List[Dict[str, Any]]) -> Dict[str, Any]:
    dims = ["identity_access","network_exposure","data_privacy","supply_chain","observability_ir"]
    score = {d: 100 for d in dims}
    findings=[]
    blockers=[]

    class Dot:
        def __init__(self, d): self.__dict__["_d"]=d
        def __getattr__(self, k):
            v=self._d.get(k)
            return Dot(v) if isinstance(v, dict) else v

    ctx = {"service": service_ctx, "bp": Dot(blueprint)}

    for r in rules:
        try:
            if safe_eval(r["condition"], ctx):
                dim = r["dimension"]
                if dim not in score:
                    continue
                score[dim] = max(0, min(100, score[dim] + int(r["score_impact"])))
                f={
                    "rule_id": r["id"],
                    "dimension": dim,
                    "severity": r["severity"],
                    "title": r["title"],
                    "description": r["description"],
                    "recommendation": r["recommendation"],
                    "is_blocker": bool(r.get("is_blocker", False)),
                    "evidence_required": r.get("evidence_required", []),
                }
                findings.append(f)
                if f["is_blocker"]:
                    blockers.append(f)
        except Exception:
            continue

    overall = round(sum(score.values())/len(score), 1)
    traffic = "green"
    if blockers or overall < 50:
        traffic = "red"
    elif overall < 80:
        traffic = "yellow"

    return {"score": {**score, "overall": overall, "traffic_light": traffic}, "findings": findings, "blockers": blockers, "evaluated_at": datetime.datetime.utcnow().isoformat()+"Z"}
