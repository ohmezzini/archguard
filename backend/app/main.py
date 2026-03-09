from __future__ import annotations
import os, datetime
from typing import List
from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from fastapi.staticfiles import StaticFiles
from sqlmodel import select

from app.core.db import init_db, get_session
from app.core.models import Service, BlueprintVersion, Evaluation, Finding, InterviewSession, InterviewTurn
from app.core.schema import Blueprint, apply_blueprint_patch
from app.core.rules_engine import load_rules, evaluate as evaluate_rules
from app.core.interview_agent import run_interview_turn
from app.core.connectors import ensure_default_sources, connector_dashboard, run_mock_securityhub_sync, findings_for_service
from app.core.ai_interview import generate_ai_followup, ai_enabled
from app.core.ai_wizard import choose_wizard_steps, BASE_WIZARD_STEPS
from app.core.seed import seed_if_empty

RULESET_PATH = os.getenv("PGAS_RULESET_PATH", "app/rules/mvp-0.1.yaml")
RULESET_VERSION = os.path.splitext(os.path.basename(RULESET_PATH))[0]

app = FastAPI(title="ArchGuard (Beta)")
app.mount("/static", StaticFiles(directory="app/static"), name="static")
templates = Jinja2Templates(directory="app/templates")
rules = load_rules(RULESET_PATH)

@app.on_event("startup")
def on_startup():
    init_db()
    with get_session() as session:
        ensure_default_sources(session)
    # Optional demo seed (idempotent). Enable with PGAS_SEED_ON_STARTUP=true
    if os.getenv('PGAS_SEED_ON_STARTUP', 'true').lower() in ['1','true','yes','y']:
        try:
            from app.core.seed import seed_if_empty
            seed_if_empty(rules, RULESET_VERSION, force=os.getenv('PGAS_SEED_FORCE','false').lower() in ['1','true','yes','y'])
        except Exception as e:
            # Don't block startup in beta; print is enough in container logs.
            print('seed failed:', e)

def get_latest_blueprint(session, service_id: int) -> BlueprintVersion | None:
    stmt = select(BlueprintVersion).where(BlueprintVersion.service_id==service_id).order_by(BlueprintVersion.version.desc()).limit(1)
    return session.exec(stmt).first()

def create_new_blueprint_version(session, service: Service, blueprint_json: dict, created_by: str) -> BlueprintVersion:
    latest = get_latest_blueprint(session, service.id)
    next_version = 1 if not latest else latest.version + 1
    bpv = BlueprintVersion(service_id=service.id, version=next_version, blueprint_json=blueprint_json, created_by=created_by)
    session.add(bpv); session.commit(); session.refresh(bpv)
    return bpv

def get_latest_evaluation(session, service_id: int) -> Evaluation | None:
    stmt = select(Evaluation).where(Evaluation.service_id==service_id).order_by(Evaluation.created_at.desc()).limit(1)
    return session.exec(stmt).first()

def get_active_interview(session, service_id: int) -> InterviewSession | None:
    stmt = select(InterviewSession).where(InterviewSession.service_id==service_id).where(InterviewSession.status=="active").order_by(InterviewSession.updated_at.desc()).limit(1)
    return session.exec(stmt).first()

def get_interview_turns(session, interview_id: int) -> List[InterviewTurn]:
    stmt = select(InterviewTurn).where(InterviewTurn.session_id==interview_id).order_by(InterviewTurn.turn_index.asc())
    return list(session.exec(stmt).all())

def get_last_turn(session, interview_id: int) -> InterviewTurn | None:
    stmt = select(InterviewTurn).where(InterviewTurn.session_id==interview_id).order_by(InterviewTurn.turn_index.desc()).limit(1)
    return session.exec(stmt).first()



@app.get("/connectors", response_class=HTMLResponse)
def connectors_page(request: Request):
    with get_session() as session:
        ensure_default_sources(session)
        dash = connector_dashboard(session)
        services = list(session.exec(select(Service)).all())
        service_map = {s.id: s.name for s in services}
        top_rows = []
        for sid, data in dash["top_services"].items():
            top_rows.append({
                "service_id": sid,
                "service_name": service_map.get(sid, f"service-{sid}"),
                "total": data["total"],
                "critical": data["critical"],
                "high": data["high"],
                "medium": data["medium"],
                "low": data["low"],
            })
        top_rows = sorted(top_rows, key=lambda x: (x["critical"], x["high"], x["total"]), reverse=True)
        return templates.TemplateResponse("connectors.html", {"request": request, "dash": dash, "top_rows": top_rows})

@app.post("/connectors/securityhub/mock-sync")
def connectors_mock_sync():
    with get_session() as session:
        run_mock_securityhub_sync(session)
    return RedirectResponse(url="/connectors", status_code=303)

@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    with get_session() as session:
        services = session.exec(select(Service).order_by(Service.updated_at.desc())).all()

        rows = []
        stats = {
            "traffic": {"green": 0, "yellow": 0, "red": 0, "unknown": 0},
            "env": {},
            "platform": {},
        }
        overall_scores = []

        for s in services:
            ev = get_latest_evaluation(session, s.id)
            traffic = ev.traffic_light if ev else "unknown"

            # rows for table
            rows.append(
                {
                    "id": s.id,
                    "name": s.name,
                    "owner_team": s.owner_team,
                    "domain": s.domain,
                    "environment": s.environment,
                    "platform": s.platform,
                    "traffic": traffic,
                }
            )

            # stats
            stats["traffic"][traffic] = stats["traffic"].get(traffic, 0) + 1

            stats["env"].setdefault(s.environment, {"green": 0, "yellow": 0, "red": 0, "unknown": 0})
            stats["env"][s.environment][traffic] = stats["env"][s.environment].get(traffic, 0) + 1

            stats["platform"].setdefault(s.platform, {"green": 0, "yellow": 0, "red": 0, "unknown": 0})
            stats["platform"][s.platform][traffic] = stats["platform"][s.platform].get(traffic, 0) + 1

            # overall score
            if ev and isinstance(ev.score_json, dict):
                ov = ev.score_json.get("overall")
                if isinstance(ov, (int, float)):
                    overall_scores.append(float(ov))

        kpis = {
            "services_total": len(services),
            "red": stats["traffic"].get("red", 0),
            "yellow": stats["traffic"].get("yellow", 0),
            "green": stats["traffic"].get("green", 0),
            "avg_overall": round(sum(overall_scores) / len(overall_scores), 1) if overall_scores else None,
        }

    return templates.TemplateResponse("home.html", {"request": request, "services": rows, "stats": stats, "kpis": kpis})


def _traffic_from_score(score: float | None) -> str:
    if score is None:
        return "unknown"
    if score >= 80:
        return "green"
    if score >= 60:
        return "yellow"
    return "red"





def _answers_from_turns(turns_by_step):
    answers = {}
    for _, turn in turns_by_step.items():
        answers.update(turn.state_update_json or {})
    return answers

def _wizard_steps_for_service(service, turns_by_step):
    answers = _answers_from_turns(turns_by_step)
    return choose_wizard_steps(service.model_dump() if hasattr(service, "model_dump") else service, answers, max_steps=10)

# ---------- Wizard interview (guided, concise, MITRE-aware) ----------

WIZARD_STEPS = [
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
        "mitre": ["T1190 Exploit Public-Facing Application", "T1078 Valid Accounts"]
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
        "mitre": ["T1190 Exploit Public-Facing Application"]
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
        "mitre": ["T1552 Unsecured Credentials", "T1078 Valid Accounts"]
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
        "mitre": ["T1020 Automated Exfiltration", "T1041 Exfiltration Over C2 Channel"]
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
        "mitre": ["T1070 Indicator Removal", "T1562 Impair Defenses"]
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
        "mitre": ["T1195 Supply Chain Compromise"]
    },
]

def _ensure_interview_session(session, service_id: int, blueprint_id: int):
    s = get_active_interview(session, service_id)
    if s:
        return s
    s = InterviewSession(service_id=service_id, blueprint_id=blueprint_id, status="active", question_budget_total=10, question_budget_remaining=10, asked_question_ids=[])
    session.add(s); session.commit(); session.refresh(s)
    return s

def _last_session_turn_by_step(session, interview_id: int):
    turns = get_interview_turns(session, interview_id)
    data = {}
    for t in turns:
        # store by turn_index-1 -> step
        data[t.turn_index - 1] = t
    return data

def _patch_from_wizard(service, answers):
    # build patch from concise wizard answers
    patch = {}
    # exposure
    if answers.get("exposure") in ["internal","partner","public"]:
        # exposure belongs to service metadata, not blueprint
        pass

    ingress = answers.get("ingress_profile")
    if ingress == "alb_oidc":
        patch.setdefault("ingress", {}).update({"type":"ALB","auth":"OIDC","waf":"yes","rate_limit":"yes"})
    elif ingress == "apigw_jwt":
        patch.setdefault("ingress", {}).update({"type":"APIGW","auth":"JWT","waf":"yes","rate_limit":"yes"})
    elif ingress == "cloudfront_mtls":
        patch.setdefault("ingress", {}).update({"type":"CloudFront","auth":"mTLS","waf":"yes","rate_limit":"yes"})
    elif ingress == "none":
        patch.setdefault("ingress", {}).update({"type":"ALB" if service.platform=="EKS" else "APIGW","auth":"none","waf":"no","rate_limit":"no"})

    ident = answers.get("identity_profile")
    if ident == "irsa":
        patch.setdefault("identity", {}).update({"workload_identity":"IRSA","iam_least_privilege":"yes","rbac":"yes"})
    elif ident == "taskrole":
        patch.setdefault("identity", {}).update({"workload_identity":"TaskRole","iam_least_privilege":"yes","rbac":"yes"})
    elif ident == "statickeys":
        patch.setdefault("identity", {}).update({"workload_identity":"StaticKeys","iam_least_privilege":"unknown","rbac":"unknown"})

    data = answers.get("data_profile")
    if data == "sensitive_encrypted":
        patch.setdefault("data", {}).update({"sensitive":"yes","encryption_at_rest":"yes","encryption_in_transit":"yes","logs_may_contain_pii":"yes","redaction":"yes"})
    elif data == "sensitive_partial":
        patch.setdefault("data", {}).update({"sensitive":"yes","encryption_at_rest":"unknown","encryption_in_transit":"yes","logs_may_contain_pii":"yes","redaction":"unknown"})
    elif data == "nonsensitive":
        patch.setdefault("data", {}).update({"sensitive":"no","encryption_at_rest":"yes","encryption_in_transit":"yes","logs_may_contain_pii":"no","redaction":"yes"})

    obs = answers.get("obs_profile")
    if obs == "strong":
        patch.setdefault("observability", {}).update({"central_logging":"yes","siem":"yes","retention_days":180})
    elif obs == "partial":
        patch.setdefault("observability", {}).update({"central_logging":"yes","siem":"unknown","retention_days":"unknown"})
    elif obs == "weak":
        patch.setdefault("observability", {}).update({"central_logging":"no","siem":"unknown","retention_days":"unknown"})

    controls = answers.get("pipeline_controls") or []
    patch.setdefault("cicd", {}).setdefault("gates", {})
    patch.setdefault("supply_chain", {})
    patch["cicd"]["gates"]["sast"] = "yes" if "sast" in controls else "unknown"
    patch["cicd"]["gates"]["sca"] = "yes" if "sca" in controls else "unknown"
    patch["cicd"]["gates"]["secrets_scan"] = "yes" if "secrets" in controls else "unknown"
    patch["supply_chain"]["container_scan"] = "yes" if "containerscan" in controls else "unknown"
    patch["supply_chain"]["sbom"] = "yes" if "sbom" in controls else "unknown"
    patch["supply_chain"]["image_signing"] = "yes" if "signing" in controls else "unknown"

    public_controls = answers.get("public_controls") or []
    if public_controls:
        patch.setdefault("ingress", {})
        patch["ingress"]["waf"] = "yes" if "waf" in public_controls else patch["ingress"].get("waf", "unknown")
        patch["ingress"]["rate_limit"] = "yes" if "rate_limit" in public_controls else patch["ingress"].get("rate_limit", "unknown")

    egress = answers.get("egress_profile")
    if egress == "restricted":
        patch.setdefault("network", {}).setdefault("egress", {}).update({"internet":"yes","restricted":"yes"})
    elif egress == "internet_limited":
        patch.setdefault("network", {}).setdefault("egress", {}).update({"internet":"yes","restricted":"unknown"})
    elif egress == "internet_open":
        patch.setdefault("network", {}).setdefault("egress", {}).update({"internet":"yes","restricted":"no"})

    secrets = answers.get("secrets_profile")
    if secrets == "manager_auto":
        patch.setdefault("secrets", {}).update({"backend":"SecretsManager","rotation":"auto"})
    elif secrets == "manager_manual":
        patch.setdefault("secrets", {}).update({"backend":"SecretsManager","rotation":"manual"})
    elif secrets == "envvar":
        patch.setdefault("secrets", {}).update({"backend":"EnvVar","rotation":"none"})

    runtime = answers.get("runtime_controls") or []
    if runtime:
        patch.setdefault("identity", {})
        if "network_policy" in runtime:
            patch["identity"]["rbac"] = patch["identity"].get("rbac", "yes")

    return patch

@app.get("/service/{service_id}/interview", response_class=HTMLResponse)
def interview_wizard(request: Request, service_id: int, step: int = 0):
    with get_session() as session:
        svc = session.get(Service, service_id)
        if not svc:
            return HTMLResponse("Not found", status_code=404)
        bpv = get_latest_blueprint(session, service_id)
        blueprint = bpv.blueprint_json if bpv else Blueprint().model_dump()

        s = _ensure_interview_session(session, service_id, bpv.id if bpv else 0)
        turns_by_step = _last_session_turn_by_step(session, s.id)
        wizard_steps = _wizard_steps_for_service(svc, turns_by_step)

        if step < 0:
            step = 0
        if step >= len(wizard_steps):
            step = len(wizard_steps) - 1

        current = wizard_steps[step]
        current_answer = None
        current_answer_multi = []
        current_answer_text = None

        if step in turns_by_step:
            try:
                state = turns_by_step[step].state_update_json or {}
                val = state.get(current["key"])
                if isinstance(val, list):
                    current_answer_multi = val
                elif isinstance(val, str):
                    current_answer = val
                    current_answer_text = val
            except Exception:
                pass

        answers = _answers_from_turns(turns_by_step)

        preview = blueprint
        try:
            patch = _patch_from_wizard(svc, answers)
            preview = apply_blueprint_patch(blueprint, patch)
        except Exception:
            pass

        ai_hint = generate_ai_followup(current, svc.model_dump(), preview, answers)
        steps = [{"index":i, "short": s0["short"]} for i,s0 in enumerate(wizard_steps)]
        return templates.TemplateResponse("interview.html", {
            "request": request,
            "sid": service_id,
            "service": svc.model_dump(),
            "step": step,
            "steps": steps,
            "step_total": len(wizard_steps),
            "current": current,
            "current_answer": current_answer,
            "current_answer_multi": current_answer_multi,
            "current_answer_text": current_answer_text,
            "preview": preview,
            "ai_hint": ai_hint,
            "ai_enabled": ai_enabled(),
        })



@app.get("/service/{service_id}/interview/result", response_class=HTMLResponse)
def interview_result(request: Request, service_id: int, before_id: int | None = None, after_id: int | None = None):
    with get_session() as session:
        svc = session.get(Service, service_id)
        if not svc:
            return HTMLResponse("Not found", status_code=404)

        before = None
        after = None

        if before_id:
            evb = session.get(Evaluation, before_id)
            if evb:
                before = {
                    "traffic": evb.traffic_light,
                    "overall": evb.score_json.get("overall") if isinstance(evb.score_json, dict) else None,
                    "identity_access": evb.score_json.get("identity_access") if isinstance(evb.score_json, dict) else None,
                    "network_exposure": evb.score_json.get("network_exposure") if isinstance(evb.score_json, dict) else None,
                    "data_privacy": evb.score_json.get("data_privacy") if isinstance(evb.score_json, dict) else None,
                    "supply_chain": evb.score_json.get("supply_chain") if isinstance(evb.score_json, dict) else None,
                    "observability_ir": evb.score_json.get("observability_ir") if isinstance(evb.score_json, dict) else None,
                }

        eva = session.get(Evaluation, after_id) if after_id else get_latest_evaluation(session, service_id)
        if not eva:
            return RedirectResponse(url=f"/service/{service_id}", status_code=303)

        after = {
            "traffic": eva.traffic_light,
            "overall": eva.score_json.get("overall") if isinstance(eva.score_json, dict) else None,
            "identity_access": eva.score_json.get("identity_access") if isinstance(eva.score_json, dict) else None,
            "network_exposure": eva.score_json.get("network_exposure") if isinstance(eva.score_json, dict) else None,
            "data_privacy": eva.score_json.get("data_privacy") if isinstance(eva.score_json, dict) else None,
            "supply_chain": eva.score_json.get("supply_chain") if isinstance(eva.score_json, dict) else None,
            "observability_ir": eva.score_json.get("observability_ir") if isinstance(eva.score_json, dict) else None,
        }

        rows = [
            {"label":"Identity & Access", "before": before.get("identity_access") if before else "—", "after": after.get("identity_access")},
            {"label":"Network Exposure", "before": before.get("network_exposure") if before else "—", "after": after.get("network_exposure")},
            {"label":"Data Protection", "before": before.get("data_privacy") if before else "—", "after": after.get("data_privacy")},
            {"label":"Supply Chain", "before": before.get("supply_chain") if before else "—", "after": after.get("supply_chain")},
            {"label":"Observability & IR", "before": before.get("observability_ir") if before else "—", "after": after.get("observability_ir")},
        ]

        delta_overall = 0
        if before and isinstance(before.get("overall"), (int, float)) and isinstance(after.get("overall"), (int, float)):
            delta_overall = round(after["overall"] - before["overall"], 1)

        after_blockers = eva.blockers_json if isinstance(eva.blockers_json, list) else []

        return templates.TemplateResponse("interview_result.html", {
            "request": request,
            "sid": service_id,
            "service": svc.model_dump(),
            "before": before,
            "after": after,
            "rows": rows,
            "delta_overall": delta_overall,
            "after_blockers": after_blockers,
        })

@app.post("/service/{service_id}/interview/next")
def interview_wizard_next(
    service_id: int,
    step: int = Form(...),
    answer: str | None = Form(None),
    answer_text: str | None = Form(None),
    answer_multi: list[str] | None = Form(None),
):
    with get_session() as session:
        svc = session.get(Service, service_id)
        if not svc:
            return JSONResponse({"error":"not found"}, status_code=404)
        bpv = get_latest_blueprint(session, service_id)
        blueprint = bpv.blueprint_json if bpv else Blueprint().model_dump()
        s = _ensure_interview_session(session, service_id, bpv.id if bpv else 0)
        turns_by_step = _last_session_turn_by_step(session, s.id)
        wizard_steps = _wizard_steps_for_service(svc, turns_by_step)

        if step < 0:
            step = 0
        if step >= len(wizard_steps):
            step = len(wizard_steps) - 1

        current = wizard_steps[step]
        value = answer
        if current["type"] == "check":
            value = answer_multi or []
        elif current["type"] == "text":
            value = answer_text or ""

        if step in turns_by_step:
            t = turns_by_step[step]
            t.user_message = str(value)
            t.assistant_message = current["title"]
            t.state_update_json = {current["key"]: value}
            session.add(t); session.commit()
        else:
            t = InterviewTurn(
                session_id=s.id,
                turn_index=step + 1,
                user_message=str(value),
                assistant_message=current["title"],
                state_update_json={current["key"]: value},
                asked_question_ids=[current["short"]],
                next_questions=[],
            )
            session.add(t); session.commit()

        turns_by_step = _last_session_turn_by_step(session, s.id)
        answers = _answers_from_turns(turns_by_step)

        if answers.get("exposure") in ["internal","partner","public"]:
            svc.exposure = answers["exposure"]
            session.add(svc); session.commit()

        patch = _patch_from_wizard(svc, answers)
        merged = apply_blueprint_patch(blueprint, patch)
        bpv2 = create_new_blueprint_version(session, svc, merged, created_by="wizard")

        s.blueprint_id = bpv2.id
        s.question_budget_total = len(wizard_steps)
        s.question_budget_remaining = max(0, len(wizard_steps) - len(turns_by_step))
        if step >= len(wizard_steps) - 1:
            s.status = "completed"
        session.add(s); session.commit()

        if step >= len(wizard_steps) - 1:
            before_ev = get_latest_evaluation(session, service_id)
            before_id = before_ev.id if before_ev else None

            service_ctx = {
                "exposure": svc.exposure,
                "platform": svc.platform,
                "environment": svc.environment,
                "criticality": svc.criticality,
                "data_classification": svc.data_classification,
            }
            result = evaluate_rules(service_ctx, bpv2.blueprint_json, rules)
            ev = Evaluation(service_id=svc.id, blueprint_id=bpv2.id, ruleset_version=RULESET_VERSION, traffic_light=result["score"]["traffic_light"], score_json=result["score"], blockers_json=result["blockers"])
            session.add(ev); session.commit(); session.refresh(ev)
            for f in result["findings"]:
                session.add(Finding(evaluation_id=ev.id, rule_id=f["rule_id"], dimension=f["dimension"], severity=f["severity"], title=f["title"], description=f["description"], recommendation=f["recommendation"], is_blocker=f["is_blocker"], evidence_required=f.get("evidence_required", [])))
            session.commit()
            svc.updated_at = datetime.datetime.utcnow()
            session.add(svc); session.commit()

            url = f"/service/{service_id}/interview/result?after_id={ev.id}"
            if before_id:
                url += f"&before_id={before_id}"
            return RedirectResponse(url=url, status_code=303)

        return RedirectResponse(url=f"/service/{service_id}/interview?step={step+1}", status_code=303)

@app.get("/scorecard", response_class=HTMLResponse)
def scorecard(request: Request):
    """Executive scorecard: mean scores per domain across latest evaluations."""
    with get_session() as session:
        services = session.exec(select(Service)).all()

        dims = {
            "identity_access": [],
            "network_exposure": [],
            "data_privacy": [],
            "supply_chain": [],
            "observability_ir": [],
        }

        for s in services:
            ev = get_latest_evaluation(session, s.id)
            if not ev or not isinstance(ev.score_json, dict):
                continue
            for k in list(dims.keys()):
                v = ev.score_json.get(k)
                if isinstance(v, (int, float)):
                    dims[k].append(float(v))

        labels = {
            "identity_access": ("Identity & Access", "Workload identity, RBAC, least privilege"),
            "network_exposure": ("Network Exposure", "Ingress auth/WAF, egress restriction, exposure"),
            "data_privacy": ("Data Protection", "Encryption, PII handling, redaction"),
            "supply_chain": ("Supply Chain", "SAST/SCA, container scan, SBOM/signing"),
            "observability_ir": ("Observability & IR", "Central logging, SIEM, retention"),
        }

        rows=[]
        radar_labels=[]
        radar_values=[]
        for k,(lab,desc) in labels.items():
            score = round(sum(dims[k])/len(dims[k]), 1) if dims[k] else None
            rows.append({"key": k, "label": lab, "desc": desc, "score": score if score is not None else "—", "traffic": _traffic_from_score(score)})
            radar_labels.append(lab)
            radar_values.append(score if score is not None else 0)

        radar={"labels": radar_labels, "values": radar_values}

    return templates.TemplateResponse("scorecard.html", {"request": request, "rows": rows, "radar": radar})


@app.get("/risk-map", response_class=HTMLResponse)
def risk_map(request: Request):
    """Risk map: Criticality × Exposure bubble chart."""
    exposure_order = ["internal", "partner", "public"]
    exposure_labels = ["Internal", "Partner", "Public"]
    criticality_order = ["low", "medium", "high"]
    criticality_labels = ["Low", "Medium", "High"]

    def x_of(exposure: str) -> int:
        return exposure_order.index(exposure) if exposure in exposure_order else 0

    def y_of(criticality: str) -> int:
        return criticality_order.index(criticality) if criticality in criticality_order else 1

    with get_session() as session:
        services = session.exec(select(Service)).all()
        points=[]
        for s in services:
            ev = get_latest_evaluation(session, s.id)
            traffic = ev.traffic_light if ev else "unknown"
            r = 8 + (3 if s.criticality == "high" else 0) + (4 if traffic == "red" else 2 if traffic == "yellow" else 0)
            points.append({"name": s.name, "traffic": traffic, "x": x_of(s.exposure), "y": y_of(s.criticality), "r": r})

    payload = {"points": points, "exposure_labels": exposure_labels, "criticality_labels": criticality_labels}
    return templates.TemplateResponse("risk_map.html", {"request": request, "payload": payload})

@app.get("/new", response_class=HTMLResponse)
def new_service(request: Request):
    return templates.TemplateResponse("new.html", {"request": request})

@app.post("/new")
def create_service(
    name: str = Form(...),
    owner_team: str = Form("unknown"),
    domain: str = Form("unknown"),
    environment: str = Form("prod"),
    platform: str = Form("EKS"),
    criticality: str = Form("high"),
    data_classification: str = Form("confidential"),
    exposure: str = Form("internal"),
):
    with get_session() as session:
        svc = Service(
            name=name,
            owner_team=owner_team,
            domain=domain,
            environment=environment,
            platform=platform,
            criticality=criticality,
            data_classification=data_classification,
            exposure=exposure,
            updated_at=datetime.datetime.utcnow(),
        )
        session.add(svc); session.commit(); session.refresh(svc)

        bp = Blueprint().model_dump()
        create_new_blueprint_version(session, svc, bp, created_by="system")

        service_id = svc.id

    return RedirectResponse(url=f"/service/{service_id}", status_code=303)

@app.get("/service/{service_id}", response_class=HTMLResponse)
def view_service(request: Request, service_id: int):
    with get_session() as session:
        svc = session.get(Service, service_id)
        if not svc:
            return HTMLResponse("Not found", status_code=404)

        bpv = get_latest_blueprint(session, service_id)
        blueprint = bpv.blueprint_json if bpv else Blueprint().model_dump()
        blueprint_version = bpv.version if bpv else 0

        ev = get_latest_evaluation(session, service_id)
        evaluation_payload=None
        findings_payload=[]
        service_tech = None
        if ev:
            f_list = session.exec(select(Finding).where(Finding.evaluation_id==ev.id)).all()
            findings_payload = [{"rule_id": f.rule_id, "dimension": f.dimension, "severity": f.severity, "title": f.title, "description": f.description, "recommendation": f.recommendation, "is_blocker": f.is_blocker} for f in f_list]
            evaluation_payload = {"score": ev.score_json, "ruleset": ev.ruleset_version, "blockers": ev.blockers_json, "traffic_light": ev.traffic_light,
                                "findings": findings_payload}
            score = ev.score_json if isinstance(ev.score_json, dict) else {}
            service_tech = {
                "domains": [
                    {"label":"Identity & Access", "value": score.get("identity_access")},
                    {"label":"Network Exposure", "value": score.get("network_exposure")},
                    {"label":"Data Protection", "value": score.get("data_privacy")},
                    {"label":"Supply Chain", "value": score.get("supply_chain")},
                    {"label":"Observability & IR", "value": score.get("observability_ir")},
                ],
                "risk_view": {
                    "criticality": svc.criticality,
                    "exposure": svc.exposure,
                    "traffic": ev.traffic_light,
                    "overall": score.get("overall"),
                }
            }

        interview_session = get_active_interview(session, service_id)
        turns=[]; last_turn=None
        if interview_session:
            turns = get_interview_turns(session, interview_session.id)
            last_turn = get_last_turn(session, interview_session.id)

        external_findings = findings_for_service(session, service_id)
        return templates.TemplateResponse("service.html", {"request": request, "sid": service_id, "service": svc.model_dump(), "blueprint": blueprint, "blueprint_version": blueprint_version, "evaluation": evaluation_payload, "interview_session": interview_session, "turns": turns, "last_turn": last_turn, "service_tech": service_tech, "external_findings": external_findings})

@app.post("/service/{service_id}/patch")
def patch_blueprint(service_id: int, patch_json: str = Form(...)):
    import json
    with get_session() as session:
        svc = session.get(Service, service_id)
        if not svc:
            return JSONResponse({"error":"not found"}, status_code=404)
        bpv = get_latest_blueprint(session, service_id)
        if not bpv:
            return JSONResponse({"error":"blueprint not found"}, status_code=404)
        try:
            patch = json.loads(patch_json)
            merged = apply_blueprint_patch(bpv.blueprint_json, patch)
        except Exception as e:
            return JSONResponse({"error": str(e)}, status_code=400)
        create_new_blueprint_version(session, svc, merged, created_by="user_patch")
        svc.updated_at=datetime.datetime.utcnow()
        session.add(svc); session.commit()
    return RedirectResponse(url=f"/service/{service_id}", status_code=303)

@app.post("/service/{service_id}/evaluate")
def run_eval(service_id: int):
    with get_session() as session:
        svc = session.get(Service, service_id)
        if not svc:
            return JSONResponse({"error":"not found"}, status_code=404)
        bpv = get_latest_blueprint(session, service_id)
        if not bpv:
            return JSONResponse({"error":"blueprint not found"}, status_code=404)

        service_ctx = {"exposure": svc.exposure, "platform": svc.platform, "environment": svc.environment, "criticality": svc.criticality, "data_classification": svc.data_classification}
        result = evaluate_rules(service_ctx, bpv.blueprint_json, rules)

        ev = Evaluation(service_id=svc.id, blueprint_id=bpv.id, ruleset_version=RULESET_VERSION, traffic_light=result["score"]["traffic_light"], score_json=result["score"], blockers_json=result["blockers"])
        session.add(ev); session.commit(); session.refresh(ev)

        for f in result["findings"]:
            session.add(Finding(evaluation_id=ev.id, rule_id=f["rule_id"], dimension=f["dimension"], severity=f["severity"], title=f["title"], description=f["description"], recommendation=f["recommendation"], is_blocker=f["is_blocker"], evidence_required=f.get("evidence_required", [])))
        session.commit()

        svc.updated_at=datetime.datetime.utcnow()
        session.add(svc); session.commit()

    return RedirectResponse(url=f"/service/{service_id}", status_code=303)


@app.get("/service/{service_id}/interview")
def interview_start_get(service_id: int):
    """Fallback for older UI versions: redirect GET to interview start flow."""
    return RedirectResponse(url=f"/service/{service_id}", status_code=303)

@app.post("/service/{service_id}/interview/start")
def interview_start(service_id: int):
    with get_session() as session:
        svc = session.get(Service, service_id)
        if not svc:
            return JSONResponse({"error":"not found"}, status_code=404)
        bpv = get_latest_blueprint(session, service_id)
        if not bpv:
            return JSONResponse({"error":"blueprint not found"}, status_code=404)
        active = get_active_interview(session, service_id)
        if active:
            return RedirectResponse(url=f"/service/{service_id}", status_code=303)

        s = InterviewSession(service_id=svc.id, blueprint_id=bpv.id, status="active", question_budget_total=12, question_budget_remaining=12, asked_question_ids=[])
        session.add(s); session.commit(); session.refresh(s)

        result = run_interview_turn(svc.model_dump(), bpv.blueprint_json, s.question_budget_remaining, s.asked_question_ids, "(início da entrevista)")
        t = InterviewTurn(session_id=s.id, turn_index=1, user_message="(início da entrevista)", assistant_message=result["assistant_message"], state_update_json=result["state_update"], asked_question_ids=result["asked_question_ids"], next_questions=result["next_questions"])
        session.add(t)

        s.question_budget_remaining = max(0, s.question_budget_remaining - len(result["asked_question_ids"]))
        s.asked_question_ids = s.asked_question_ids + result["asked_question_ids"]
        s.updated_at=datetime.datetime.utcnow()
        session.add(s); session.commit()

    return RedirectResponse(url=f"/service/{service_id}", status_code=303)

@app.post("/service/{service_id}/interview/turn")
def interview_turn(service_id: int, user_message: str = Form(...)):
    with get_session() as session:
        svc = session.get(Service, service_id)
        if not svc:
            return JSONResponse({"error":"not found"}, status_code=404)
        bpv = get_latest_blueprint(session, service_id)
        if not bpv:
            return JSONResponse({"error":"blueprint not found"}, status_code=404)
        s = get_active_interview(session, service_id)
        if not s:
            return JSONResponse({"error":"no active interview session"}, status_code=400)

        last = get_last_turn(session, s.id)
        next_index = 1 if not last else last.turn_index + 1

        result = run_interview_turn(svc.model_dump(), bpv.blueprint_json, s.question_budget_remaining, s.asked_question_ids, user_message)

        if result["state_update"]:
            merged = apply_blueprint_patch(bpv.blueprint_json, result["state_update"])
            bpv2 = create_new_blueprint_version(session, svc, merged, created_by="interview")
            s.blueprint_id = bpv2.id

        t = InterviewTurn(session_id=s.id, turn_index=next_index, user_message=user_message, assistant_message=result["assistant_message"], state_update_json=result["state_update"], asked_question_ids=result["asked_question_ids"], next_questions=result["next_questions"])
        session.add(t)

        s.question_budget_remaining = max(0, s.question_budget_remaining - len(result["asked_question_ids"]))
        s.asked_question_ids = s.asked_question_ids + result["asked_question_ids"]
        s.updated_at=datetime.datetime.utcnow()
        if s.question_budget_remaining <= 0:
            s.status="completed"
        session.add(s); session.commit()

        svc.updated_at=datetime.datetime.utcnow()
        session.add(svc); session.commit()

    return RedirectResponse(url=f"/service/{service_id}", status_code=303)

@app.post("/service/{service_id}/interview/reset")
def interview_reset(service_id: int):
    with get_session() as session:
        active = get_active_interview(session, service_id)
        if active:
            active.status="completed"
            active.updated_at=datetime.datetime.utcnow()
            session.add(active); session.commit()
    return RedirectResponse(url=f"/service/{service_id}", status_code=303)

@app.post("/admin/seed")
def admin_seed(force: bool = True):
    """Dev-only: (re)seed demo data. If force=True wipes existing rows first."""
    try:
        result = seed_if_empty(rules, RULESET_VERSION, force=force)
        return result
    except Exception as e:
        return JSONResponse({"error": str(e)}, status_code=500)
