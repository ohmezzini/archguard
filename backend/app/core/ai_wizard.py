from __future__ import annotations

import json
import os
from typing import Any, Dict, List

from openai import OpenAI

AI_MODE = os.getenv("ARCHGUARD_AI_MODE", "smart").lower()
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5.4")


def ai_enabled() -> bool:
    return AI_MODE == "smart" and bool(os.getenv("OPENAI_API_KEY"))


BASE_WIZARD_STEPS: List[Dict[str, Any]] = [
    {
        "short": "Exposure",
        "title": "Como o serviço é exposto?",
        "description": "Definimos primeiro a superfície de ataque e os controles de borda. Isso guia o risco arquitetural.",
        "type": "radio",
        "key": "exposure",
        "options": [
            {"value": "internal", "label": "Internal", "hint": "Acesso apenas interno."},
            {"value": "partner", "label": "Partner", "hint": "Integração com parceiros / B2B."},
            {"value": "public", "label": "Public", "hint": "Exposto à internet."},
        ],
        "mitre": ["T1190 Exploit Public-Facing Application", "T1078 Valid Accounts"],
    },
    {
        "short": "Ingress",
        "title": "Qual é o desenho de entrada e autenticação?",
        "description": "Escolha o tipo de ingresso e o método de autenticação predominante.",
        "type": "radio",
        "key": "ingress_profile",
        "options": [
            {"value": "alb_oidc", "label": "ALB + OIDC", "hint": "Borda autenticada com provedor de identidade."},
            {"value": "apigw_jwt", "label": "API Gateway + JWT", "hint": "Proteção de API com token."},
            {"value": "cloudfront_mtls", "label": "CloudFront + mTLS", "hint": "Canal autenticado por certificado."},
            {"value": "none", "label": "Sem autenticação", "hint": "Maior risco, geralmente inadequado para public."},
        ],
        "mitre": ["T1190 Exploit Public-Facing Application"],
    },
    {
        "short": "Identity",
        "title": "Como o workload acessa recursos na AWS?",
        "description": "Isso define risco de credenciais e rastreabilidade.",
        "type": "radio",
        "key": "identity_profile",
        "options": [
            {"value": "irsa", "label": "IRSA", "hint": "Ideal para EKS."},
            {"value": "taskrole", "label": "TaskRole", "hint": "Ideal para ECS."},
            {"value": "statickeys", "label": "Static Keys", "hint": "Alto risco; evitar."},
        ],
        "mitre": ["T1552 Unsecured Credentials", "T1078 Valid Accounts"],
    },
    {
        "short": "Data",
        "title": "Há dados sensíveis e como estão protegidos?",
        "description": "Queremos entender confidencialidade e proteção contra vazamento.",
        "type": "radio",
        "key": "data_profile",
        "options": [
            {"value": "sensitive_encrypted", "label": "Sensíveis + at-rest + in-transit", "hint": "Controles de criptografia evidenciados."},
            {"value": "sensitive_partial", "label": "Sensíveis + proteção parcial", "hint": "Há lacunas em at-rest ou in-transit."},
            {"value": "nonsensitive", "label": "Sem dados sensíveis", "hint": "Menor impacto regulatório."},
        ],
        "mitre": ["T1020 Automated Exfiltration", "T1041 Exfiltration Over C2 Channel"],
    },
    {
        "short": "Logs",
        "title": "Como estão logs, SIEM e retenção?",
        "description": "Isso influencia detecção, resposta e evidência para auditoria.",
        "type": "radio",
        "key": "obs_profile",
        "options": [
            {"value": "strong", "label": "Central logging + SIEM + retenção definida", "hint": "Boa rastreabilidade."},
            {"value": "partial", "label": "Logging parcial / SIEM desconhecido", "hint": "Pode dificultar resposta a incidentes."},
            {"value": "weak", "label": "Baixa evidência de logging", "hint": "Risco operacional."},
        ],
        "mitre": ["T1070 Indicator Removal", "T1562 Impair Defenses"],
    },
    {
        "short": "Shift-left",
        "title": "Quais gates de segurança existem no pipeline?",
        "description": "Selecione os controles já presentes. Quanto mais evidência no pipeline, melhor o posture score.",
        "type": "check",
        "key": "pipeline_controls",
        "options": [
            {"value": "sast", "label": "SAST", "hint": "Análise estática de código."},
            {"value": "sca", "label": "SCA", "hint": "Dependências e vulnerabilidades conhecidas."},
            {"value": "secrets", "label": "Secrets Scan", "hint": "Busca por segredos expostos."},
            {"value": "containerscan", "label": "Container Scan", "hint": "Imagem de container escaneada."},
            {"value": "sbom", "label": "SBOM", "hint": "Bill of materials do software."},
            {"value": "signing", "label": "Image Signing", "hint": "Assinatura de imagem."},
        ],
        "mitre": ["T1195 Supply Chain Compromise"],
    },
]

FOLLOW_UP_LIBRARY: Dict[str, Dict[str, Any]] = {
    "public_controls": {
        "short": "Public Controls",
        "title": "Quais controles extras existem para exposição pública?",
        "description": "Serviços públicos precisam de proteção de borda e monitoramento adicional.",
        "type": "check",
        "key": "public_controls",
        "options": [
            {"value": "waf", "label": "WAF", "hint": "Proteção contra exploração comum."},
            {"value": "rate_limit", "label": "Rate limiting", "hint": "Reduz abuso e brute force."},
            {"value": "bot", "label": "Bot / anomaly protection", "hint": "Detecção de comportamento automatizado."},
            {"value": "geo", "label": "Geo/IP restrictions", "hint": "Restrições adicionais por origem."},
        ],
        "mitre": ["T1190 Exploit Public-Facing Application", "T1110 Brute Force"],
    },
    "egress": {
        "short": "Egress",
        "title": "Como está o controle de saída (egress)?",
        "description": "Queremos reduzir risco de exfiltração e C2 por saídas liberadas.",
        "type": "radio",
        "key": "egress_profile",
        "options": [
            {"value": "restricted", "label": "Egress restrito", "hint": "Allowlist / proxy / egress gateway."},
            {"value": "internet_limited", "label": "Internet liberada com alguma restrição", "hint": "Parcial."},
            {"value": "internet_open", "label": "Internet aberta", "hint": "Maior risco."},
        ],
        "mitre": ["T1041 Exfiltration Over C2 Channel", "T1105 Ingress Tool Transfer"],
    },
    "secrets": {
        "short": "Secrets",
        "title": "Como os segredos são armazenados e rotacionados?",
        "description": "Isso afeta risco de vazamento de credenciais e governança.",
        "type": "radio",
        "key": "secrets_profile",
        "options": [
            {"value": "manager_auto", "label": "Secrets Manager / Vault + rotação automática", "hint": "Estado desejado."},
            {"value": "manager_manual", "label": "Secrets Manager / Vault + rotação manual", "hint": "Melhor que none."},
            {"value": "envvar", "label": "Variáveis de ambiente / prática fraca", "hint": "Maior risco."},
        ],
        "mitre": ["T1552 Unsecured Credentials"],
    },
    "runtime": {
        "short": "Runtime",
        "title": "Há hardening e governança no runtime?",
        "description": "Queremos entender proteção operacional do workload.",
        "type": "check",
        "key": "runtime_controls",
        "options": [
            {"value": "readonly_fs", "label": "Read-only filesystem", "hint": "Reduz escrita indevida no container."},
            {"value": "non_root", "label": "Run as non-root", "hint": "Menor privilégio no runtime."},
            {"value": "seccomp", "label": "Seccomp/AppArmor/PSP equivalentes", "hint": "Restrições adicionais."},
            {"value": "network_policy", "label": "Network policies", "hint": "Segmentação leste-oeste."},
        ],
        "mitre": ["T1611 Escape to Host", "T1610 Deploy Container"],
    },
}


def _client() -> OpenAI:
    return OpenAI()


def generate_ai_followup(step: Dict[str, Any], service: Dict[str, Any], blueprint: Dict[str, Any], answers: Dict[str, Any]) -> Dict[str, Any]:
    # sidebar copilot message only
    if not ai_enabled():
        return _fallback_sidebar(step, service, answers)

    payload = {
        "service": service,
        "step": step,
        "answers_so_far": answers,
        "blueprint_partial": blueprint,
        "task": (
            "Generate ONE concise follow-up security question in Brazilian Portuguese, "
            "plus a short why, up to 3 relevant MITRE ATT&CK techniques, and one short recommendation. "
            "Return JSON with keys: question, why, mitre, recommendation."
        ),
    }
    try:
        resp = _client().responses.create(model=OPENAI_MODEL, input=json.dumps(payload, ensure_ascii=False))
        text = (getattr(resp, "output_text", "") or "").strip()
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end != -1 and end > start:
            data = json.loads(text[start:end+1])
            return {
                "question": str(data.get("question", ""))[:500],
                "why": str(data.get("why", ""))[:300],
                "mitre": list(data.get("mitre", []))[:3],
                "recommendation": str(data.get("recommendation", ""))[:300],
            }
    except Exception:
        pass
    return _fallback_sidebar(step, service, answers)


def _fallback_sidebar(step: Dict[str, Any], service: Dict[str, Any], answers: Dict[str, Any]) -> Dict[str, Any]:
    risk = list(step.get("mitre", []))[:2]
    q = f"Confirme evidências mínimas para {step.get('short', 'esta etapa')}."
    if step.get("key") == "ingress_profile" and service.get("exposure") == "public":
        q = "Há WAF, rate limiting e autenticação na borda com evidência verificável?"
    return {
        "question": q,
        "why": "Pergunta adicional orientada a risco para reduzir incerteza antes do score final.",
        "mitre": risk,
        "recommendation": "Colete evidência objetiva de configuração, política ou pipeline.",
    }


def _fallback_choose_steps(service: Dict[str, Any], answers: Dict[str, Any], max_steps: int) -> List[Dict[str, Any]]:
    steps = list(BASE_WIZARD_STEPS)
    exposure = answers.get("exposure") or service.get("exposure")
    if exposure == "public":
        steps.append(FOLLOW_UP_LIBRARY["public_controls"])
    steps.append(FOLLOW_UP_LIBRARY["egress"])
    steps.append(FOLLOW_UP_LIBRARY["secrets"])
    steps.append(FOLLOW_UP_LIBRARY["runtime"])
    # dedupe/truncate
    out = []
    seen = set()
    for s in steps:
        if s["key"] not in seen:
            out.append(s)
            seen.add(s["key"])
        if len(out) >= max_steps:
            break
    return out


def choose_wizard_steps(service: Dict[str, Any], answers: Dict[str, Any], max_steps: int = 10) -> List[Dict[str, Any]]:
    max_steps = max(6, min(max_steps, 10))
    if not ai_enabled():
        return _fallback_choose_steps(service, answers, max_steps)

    payload = {
        "service": service,
        "answers_so_far": answers,
        "base_steps": BASE_WIZARD_STEPS,
        "extra_library": FOLLOW_UP_LIBRARY,
        "task": (
            "Select between 6 and 10 wizard steps for this service. "
            "Always include base coverage across exposure, ingress, identity, data, logging, and shift-left. "
            "Add extra steps only if useful. Return a JSON array of keys from base or extra library. "
            "Valid base keys: exposure, ingress_profile, identity_profile, data_profile, obs_profile, pipeline_controls. "
            "Valid extra keys: public_controls, egress_profile, secrets_profile, runtime_controls."
        ),
    }
    try:
        resp = _client().responses.create(model=OPENAI_MODEL, input=json.dumps(payload, ensure_ascii=False))
        text = (getattr(resp, "output_text", "") or "").strip()
        start, end = text.find("["), text.rfind("]")
        if start != -1 and end != -1 and end > start:
            keys = json.loads(text[start:end+1])
            base_map = {s["key"]: s for s in BASE_WIZARD_STEPS}
            extra_map = {
                "public_controls": FOLLOW_UP_LIBRARY["public_controls"],
                "egress_profile": FOLLOW_UP_LIBRARY["egress"],
                "secrets_profile": FOLLOW_UP_LIBRARY["secrets"],
                "runtime_controls": FOLLOW_UP_LIBRARY["runtime"],
            }
            out = []
            seen = set()
            for k in keys:
                if k in base_map and k not in seen:
                    out.append(base_map[k]); seen.add(k)
                elif k in extra_map and k not in seen:
                    out.append(extra_map[k]); seen.add(k)
            if len(out) >= 6:
                return out[:max_steps]
    except Exception:
        pass
    return _fallback_choose_steps(service, answers, max_steps)
