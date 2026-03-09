from __future__ import annotations

import json
import os
from typing import Any, Dict, List

from openai import OpenAI

AI_MODE = os.getenv("ARCHGUARD_AI_MODE", "smart").lower()
OPENAI_MODEL = os.getenv("OPENAI_MODEL", "gpt-5.4")


def ai_enabled() -> bool:
    return AI_MODE == "smart" and bool(os.getenv("OPENAI_API_KEY"))


def _fallback(step: Dict[str, Any], service: Dict[str, Any], answers: Dict[str, Any]) -> Dict[str, Any]:
    risk = []
    if service.get("exposure") == "public":
        risk.append("T1190 Exploit Public-Facing Application")
    if answers.get("identity_profile") == "statickeys":
        risk.append("T1552 Unsecured Credentials")
    if answers.get("data_profile") in ["sensitive_partial", "sensitive_encrypted"]:
        risk.append("T1020 Automated Exfiltration")
    if not risk:
        risk = step.get("mitre", [])[:2]

    q = f"Confirme evidências mínimas para {step.get('short','o controle atual')}."
    if step.get("key") == "ingress_profile" and service.get("exposure") == "public":
        q = "Há WAF, rate limiting e autenticação na borda com evidência verificável?"
    elif step.get("key") == "identity_profile":
        q = "Há evidência de least privilege e segregação de funções para esse workload?"
    elif step.get("key") == "obs_profile":
        q = "Os logs chegam ao SIEM com retenção definida e correlação por trace/request id?"

    return {
        "question": q,
        "why": "Pergunta adicional orientada a risco para reduzir incerteza antes do score final.",
        "mitre": risk,
        "recommendation": "Colete evidência objetiva (config, policy, screenshot, pipeline output).",
    }


def generate_ai_followup(step: Dict[str, Any], service: Dict[str, Any], blueprint: Dict[str, Any], answers: Dict[str, Any]) -> Dict[str, Any]:
    if not ai_enabled():
        return _fallback(step, service, answers)

    client = OpenAI()
    prompt = {
        "service": service,
        "step": {
            "short": step.get("short"),
            "title": step.get("title"),
            "description": step.get("description"),
            "mitre_seed": step.get("mitre", []),
        },
        "answers_so_far": answers,
        "blueprint_partial": blueprint,
        "task": (
            "You are a principal cloud security architect. "
            "Generate ONE concise follow-up question for this wizard step, in Brazilian Portuguese, "
            "adapted to the current answers. Also explain briefly why it matters, name up to 3 relevant MITRE ATT&CK techniques, "
            "and provide one short recommendation. Return valid JSON with keys: question, why, mitre, recommendation."
        ),
    }

    try:
        response = client.responses.create(
            model=OPENAI_MODEL,
            input=json.dumps(prompt, ensure_ascii=False),
        )
        text = getattr(response, "output_text", "") or ""
        text = text.strip()

        # best-effort JSON extraction
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            data = json.loads(text[start:end+1])
            return {
                "question": str(data.get("question", ""))[:400],
                "why": str(data.get("why", ""))[:300],
                "mitre": list(data.get("mitre", []))[:3],
                "recommendation": str(data.get("recommendation", ""))[:300],
            }
    except Exception:
        pass

    return _fallback(step, service, answers)
