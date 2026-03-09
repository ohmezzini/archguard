from __future__ import annotations
from typing import Any, Dict, List, Tuple
import re
from app.core.schema import apply_blueprint_patch

QUESTION_ORDER = ["Q2","Q3","Q4","Q8","Q6","Q9","Q13","Q5"]

def _pick_next_question(service: Dict[str, Any], bp: Dict[str, Any]) -> str:
    if bp["ingress"]["type"] == "Unknown":
        return "Q2"
    if bp["ingress"]["auth"] == "Unknown":
        return "Q3"
    if bp["ingress"]["waf"] == "unknown" and service.get("exposure") == "public":
        return "Q4"
    if bp["secrets"]["backend"] == "Unknown":
        return "Q8"
    if bp["identity"]["workload_identity"] == "Unknown":
        return "Q6"
    if bp["data"]["sensitive"] == "unknown":
        return "Q9"
    if bp["observability"]["central_logging"] == "unknown":
        return "Q13"
    if bp["network"]["egress"]["internet"] == "unknown":
        return "Q5"
    return "Q5"

def _question_text(qid: str) -> Tuple[str, str, List[str]]:
    m = {
        "Q2": ("O ingresso é ALB, APIGW, CloudFront ou None?", "Define trust boundary e controles de borda.", ["ALB","APIGW","CloudFront","None"]),
        "Q3": ("Qual autenticação no ingresso (none, OIDC, JWT, mTLS)?", "Sem autenticação no ponto de entrada, o risco cresce.", ["none","OIDC","JWT","mTLS"]),
        "Q4": ("WAF e rate limiting estão habilitados? (yes/no)", "Reduz exploração comum e abuso.", ["waf: yes/no", "rate_limit: yes/no"]),
        "Q8": ("Segredos: backend (SecretsManager/SSM/Vault/EnvVar) e rotação (auto/manual/none)?", "Segredos/rotação são fonte recorrente de incidentes.", ["SecretsManager","SSM","Vault","EnvVar","rotation:auto/manual/none"]),
        "Q6": ("Workload identity: IRSA/TaskRole/StaticKeys?", "Chaves estáticas em runtime são risco crítico.", ["IRSA","TaskRole","StaticKeys"]),
        "Q9": ("Dados sensíveis? Criptografia at-rest/in-transit (yes/no)?", "Dados sensíveis sem criptografia é bloqueador comum.", ["sensitive: yes/no", "encryption_at_rest: yes/no", "encryption_in_transit: yes/no"]),
        "Q13": ("Observabilidade: logging centralizado e SIEM (yes/no)?", "Sem trilha você não investiga incidente.", ["central_logging","siem"]),
        "Q5": ("Egress para internet? É restrito? Quais domínios?", "Egress aberto aumenta blast radius.", ["internet: yes/no", "restricted: yes/no", "allowed_domains"]),
    }
    return m.get(qid, ("Pode descrever o desenho?", "Precisamos fechar lacunas para avaliar risco.", []))

def _extract_patch_from_text(text: str) -> Dict[str, Any]:
    t = text.lower()
    patch: Dict[str, Any] = {}

    if "alb" in t: patch.setdefault("ingress", {})["type"] = "ALB"
    if "apigw" in t or "api gateway" in t: patch.setdefault("ingress", {})["type"] = "APIGW"
    if "cloudfront" in t: patch.setdefault("ingress", {})["type"] = "CloudFront"
    if re.search(r"\boidc\b", t): patch.setdefault("ingress", {})["auth"] = "OIDC"
    if re.search(r"\bjwt\b", t): patch.setdefault("ingress", {})["auth"] = "JWT"
    if "mtls" in t: patch.setdefault("ingress", {})["auth"] = "mTLS"
    if "sem autentica" in t or "auth none" in t: patch.setdefault("ingress", {})["auth"] = "none"
    if "waf" in t and ("yes" in t or "sim" in t or "habil" in t): patch.setdefault("ingress", {})["waf"] = "yes"
    if "waf" in t and ("no" in t or "nao" in t or "não" in t): patch.setdefault("ingress", {})["waf"] = "no"
    if "rate" in t and ("yes" in t or "sim" in t): patch.setdefault("ingress", {})["rate_limit"] = "yes"
    if "rate" in t and ("no" in t or "nao" in t or "não" in t): patch.setdefault("ingress", {})["rate_limit"] = "no"

    if "irsa" in t: patch.setdefault("identity", {})["workload_identity"] = "IRSA"
    if "taskrole" in t or "task role" in t: patch.setdefault("identity", {})["workload_identity"] = "TaskRole"
    if "static" in t and "key" in t: patch.setdefault("identity", {})["workload_identity"] = "StaticKeys"

    if "secrets manager" in t: patch.setdefault("secrets", {})["backend"] = "SecretsManager"
    if "ssm" in t or "parameter store" in t: patch.setdefault("secrets", {})["backend"] = "SSM"
    if "vault" in t: patch.setdefault("secrets", {})["backend"] = "Vault"
    if "env" in t and ("var" in t or "vari" in t): patch.setdefault("secrets", {})["backend"] = "EnvVar"
    if "rotacao" in t and ("auto" in t or "automat" in t): patch.setdefault("secrets", {})["rotation"] = "auto"
    if "rotacao" in t and "manual" in t: patch.setdefault("secrets", {})["rotation"] = "manual"
    if "sem rot" in t: patch.setdefault("secrets", {})["rotation"] = "none"

    if "dados sens" in t or "dado sens" in t or "pii" in t: patch.setdefault("data", {})["sensitive"] = "yes"
    if "nao tem dado sens" in t or "não tem dado sens" in t: patch.setdefault("data", {})["sensitive"] = "no"
    if "at-rest" in t and ("yes" in t or "sim" in t): patch.setdefault("data", {})["encryption_at_rest"] = "yes"
    if "at-rest" in t and ("no" in t or "nao" in t or "não" in t): patch.setdefault("data", {})["encryption_at_rest"] = "no"
    if "in-transit" in t and ("yes" in t or "sim" in t): patch.setdefault("data", {})["encryption_in_transit"] = "yes"
    if "in-transit" in t and ("no" in t or "nao" in t or "não" in t): patch.setdefault("data", {})["encryption_in_transit"] = "no"

    if "logging central" in t or "logs central" in t: patch.setdefault("observability", {})["central_logging"] = "yes"
    if "siem" in t and ("yes" in t or "sim" in t): patch.setdefault("observability", {})["siem"] = "yes"

    if "egress" in t and "internet" in t and ("yes" in t or "sim" in t): patch.setdefault("network", {}).setdefault("egress", {})["internet"] = "yes"
    if "egress" in t and "internet" in t and ("no" in t or "nao" in t or "não" in t): patch.setdefault("network", {}).setdefault("egress", {})["internet"] = "no"

    return patch

def run_interview_turn(service_ctx: Dict[str, Any], current_blueprint: Dict[str, Any], question_budget_remaining: int, asked_ids: List[str], user_message: str) -> Dict[str, Any]:
    patch = _extract_patch_from_text(user_message)
    merged = apply_blueprint_patch(current_blueprint, patch) if patch else current_blueprint

    asked_now: List[str] = []
    if question_budget_remaining > 0:
        q1 = _pick_next_question(service_ctx, merged)
        if q1 not in asked_ids:
            asked_now.append(q1)
    if question_budget_remaining - len(asked_now) > 0 and len(asked_now) < 2:
        for qid in QUESTION_ORDER:
            if qid not in (asked_ids + asked_now):
                asked_now.append(qid); break

    parts=[]
    for qid in asked_now[:2]:
        q, why, opts = _question_text(qid)
        if opts:
            parts.append(f"{qid}) {q} Opções: {', '.join(opts)}. Motivo: {why}")
        else:
            parts.append(f"{qid}) {q} Motivo: {why}")

    assistant_message = " | ".join(parts) if parts else "Entrevista concluída para o escopo do MVP."
    next_questions=[]
    for qid in QUESTION_ORDER:
        if qid not in (asked_ids + asked_now):
            next_questions.append(qid)
        if len(next_questions)==3: break

    return {"assistant_message": assistant_message, "state_update": patch, "asked_question_ids": asked_now, "next_questions": next_questions}
