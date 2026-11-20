"""API de la plateforme SecOps : /api/secops/*  (authentification obligatoire, RBAC côté serveur).

Les routes historiques du lab (/api/chat, /api/ctf/*, /api/mcp/call...) ne sont pas modifiées : elles restent
volontairement sans authentification, car elles constituent la CIBLE du laboratoire.
"""
import hashlib
import json
import time
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

import config

from . import auth, catalog, db, detection, engine, metrics, reports, runners

router = APIRouter(prefix="/api/secops")
ROOT = Path(__file__).resolve().parents[2]


# ------------------------------------------------------------------ helpers
def _token(request: Request):
    return request.cookies.get(auth.COOKIE)


def _ip(request: Request) -> str:
    return request.client.host if request.client else "-"


def current(request: Request) -> dict:
    u = auth.user_from_token(_token(request))
    if not u:
        raise HTTPException(401, "Authentification requise.")
    if request.method in ("POST", "PATCH", "PUT", "DELETE") and \
            request.headers.get(auth.CSRF_HEADER, "").lower() != auth.CSRF_VALUE:
        raise HTTPException(403, "En-tête anti-CSRF manquant.")
    return u


def need(u: dict, perm: str) -> None:
    try:
        auth.require(u, perm)
    except auth.AuthError as exc:
        raise HTTPException(exc.status, exc.message)


def audit(u: dict | None, action: str, target: str = "", details: dict | None = None, ip: str = "-") -> None:
    db.insert("audit_log", {"at": db.now(), "username": u["username"] if u else None, "role": u["role"] if u else None,
                            "action": action, "target": target, "details": details or {}, "ip": ip})


def _team_of(scenario_id: str) -> str:
    sc = catalog.BY_ID.get(scenario_id)
    if not sc:
        raise HTTPException(404, "Scénario inconnu.")
    return sc["team"]


def _visible(u: dict) -> list[str]:
    return auth.visible_teams(u)


# ------------------------------------------------------------------ modèles
class Login(BaseModel):
    username: str
    password: str


class Run(BaseModel):
    mode: str = "vulnerable"


class Campaign(BaseModel):
    team: str
    include_hardened: bool = False


class Transition(BaseModel):
    to: str
    note: str = ""


class FindingPatch(BaseModel):
    owner: str | None = None
    mitigation: str | None = None
    impact: str | None = None
    description: str | None = None


class Probe(BaseModel):
    message: str
    mode: str = "vulnerable"
    category: str = ""


class ToolCall(BaseModel):
    tool: str
    args: dict = {}
    mode: str = "vulnerable"


class Gateway(BaseModel):
    product: str = "Casque audio"
    author: str = "Client"
    text: str
    mode: str = "vulnerable"


def _mode(m: str) -> str:
    if m not in ("vulnerable", "hardened"):
        raise HTTPException(422, "mode doit valoir 'vulnerable' ou 'hardened'.")
    return m


# ------------------------------------------------------------------ authentification
@router.post("/auth/login")
def login(body: Login, request: Request):
    try:
        token, u = auth.login(body.username.strip()[:64], body.password[:256], _ip(request))
    except auth.AuthError as exc:
        audit({"username": body.username[:64], "role": None}, "auth.login_failed", body.username[:64], ip=_ip(request))
        return JSONResponse({"detail": exc.message}, status_code=exc.status)
    audit(u, "auth.login", u["username"], ip=_ip(request))
    resp = JSONResponse({"user": auth.public_user(u)})
    resp.set_cookie(auth.COOKIE, token, max_age=auth.SESSION_TTL, httponly=True, samesite="strict", path="/")
    return resp


@router.post("/auth/logout")
def logout(request: Request):
    u = auth.user_from_token(_token(request))
    auth.logout(_token(request))
    if u:
        audit(u, "auth.logout", u["username"], ip=_ip(request))
    resp = JSONResponse({"ok": True})
    resp.delete_cookie(auth.COOKIE, path="/")
    return resp


@router.get("/auth/me")
def me(request: Request):
    return {"user": auth.public_user(current(request))}


# ------------------------------------------------------------------ référentiel
@router.get("/meta")
def meta(request: Request):
    u = current(request)
    return {"teams": catalog.TEAMS, "blue": catalog.BLUE, "statuses": catalog.STATUSES,
            "roles": {k: {"label": v["label"], "team": v["team"], "permissions": sorted(auth.PERMISSIONS[k])}
                      for k, v in auth.ROLES.items()},
            "pipelines": catalog.PIPELINES, "detection_rules": [{"id": k, "name": v[0], "severity": v[1]}
                                                                 for k, v in detection.RULES.items()],
            "lab": {"model": config.CHAT_MODEL, "embed_model": config.EMBED_MODEL, "ollama": config.OLLAMA_HOST,
                    "player_id": config.PLAYER_ID,
                    "default_password": auth.using_default_password() and u["role"] == "admin"},
            "ctf_team": catalog.CTF_TEAM, "ctf_category": catalog.CTF_CATEGORY}


@router.get("/health")
def health(request: Request):
    current(request)
    import orchestrator
    t = time.time()
    llm = orchestrator.llm_available()
    try:
        import mcp  # noqa: F401
        mcp_ok = True
    except Exception:
        mcp_ok = False
    try:
        orchestrator.get_store()
        rag_ok = True
    except Exception:
        rag_ok = False
    return {"llm": llm, "mcp": mcp_ok, "rag": rag_ok, "shop_db": (ROOT / "data" / "shop.db").exists(),
            "checked_in_ms": int((time.time() - t) * 1000), "secure_mode_global": config.state["secure"]}


@router.get("/scenarios")
def scenarios(request: Request, team: str = ""):
    u = current(request)
    teams = [team] if team else _visible(u)
    for t in teams:
        need(u, f"evidence:{t}")
    last = {}
    for e in db.q("SELECT scenario_id, mode, outcome, status, started_at, id FROM executions ORDER BY started_at"):
        last[(e["scenario_id"], e["mode"])] = e
    out = []
    for s in catalog.SCENARIOS:
        if s["team"] in teams:
            out.append({**{k: v for k, v in s.items() if k != "runner"},
                        "last_vulnerable": last.get((s["id"], "vulnerable")),
                        "last_hardened": last.get((s["id"], "hardened")),
                        "finding": db.q1("SELECT id, status FROM findings WHERE scenario_id=?", (s["id"],))})
    return {"scenarios": out}


@router.post("/scenarios/{scenario_id}/run")
async def run(scenario_id: str, body: Run, request: Request):
    u = current(request)
    sc = catalog.BY_ID.get(scenario_id)
    if not sc:
        raise HTTPException(404, "Scénario inconnu.")
    need(u, "run:XC" if sc.get("chain") else f"run:{sc['team']}")
    res = await engine.execute(scenario_id, _mode(body.mode), u["username"])
    audit(u, "scenario.run", scenario_id, {"mode": body.mode, "execution": res["id"], "outcome": res["outcome"],
                                           "status": res["status"]}, _ip(request))
    return res


@router.post("/campaign")
async def campaign(body: Campaign, request: Request):
    """Lance tous les scénarios déterministes (sans LLM) d'une équipe, + trafic légitime, + option mode durci."""
    u = current(request)
    if body.team not in catalog.TEAMS:
        raise HTTPException(404, "Équipe inconnue.")
    need(u, f"run:{body.team}")
    results = []
    for s in catalog.scenarios_for(body.team):
        if s["requires_llm"] or s.get("chain"):
            continue
        results.append(await engine.execute(s["id"], "vulnerable", u["username"]))
        if body.include_hardened:
            results.append(await engine.execute(s["id"], "hardened", u["username"]))
    audit(u, "campaign.run", body.team, {"executions": len(results), "hardened": body.include_hardened}, _ip(request))
    return {"executions": [{k: r[k] for k in ("id", "scenario_id", "mode", "status", "outcome", "detected",
                                              "finding_id", "summary")} for r in results]}


@router.get("/executions")
def executions(request: Request, team: str = "", limit: int = 200, scenario: str = ""):
    u = current(request)
    teams = _visible(u)
    if team:
        need(u, f"evidence:{team}")
        teams = [team]
    rows = db.q(f"SELECT * FROM executions WHERE team IN ({','.join('?' * len(teams))}) "
                + ("AND scenario_id=? " if scenario else "") + "ORDER BY started_at DESC LIMIT ?",
                (*teams, *([scenario] if scenario else []), max(1, min(limit, 1000)))) if teams else []
    return {"executions": rows}


@router.get("/executions/{exe_id}")
def execution(exe_id: str, request: Request):
    u = current(request)
    e = db.q1("SELECT * FROM executions WHERE id=?", (exe_id,))
    if not e:
        raise HTTPException(404, "Exécution introuvable.")
    need(u, f"evidence:{e['team']}")
    ev = db.q1("SELECT * FROM evidence WHERE execution_id=?", (exe_id,))
    events = db.q("SELECT * FROM security_events WHERE execution_id=?", (exe_id,))
    return {"execution": e, "evidence": ev, "events": events}


# ------------------------------------------------------------------ registre des vulnérabilités
@router.get("/findings")
def findings(request: Request):
    current(request)
    return {"findings": db.q("SELECT * FROM findings ORDER BY created_at DESC")}


@router.get("/findings/{fid}")
def finding(fid: str, request: Request):
    u = current(request)
    f = db.q1("SELECT * FROM findings WHERE id=?", (fid,))
    if not f:
        raise HTTPException(404, "Finding introuvable.")
    hist = db.q("SELECT * FROM finding_history WHERE finding_id=? ORDER BY at", (fid,))
    exes = db.q("SELECT * FROM executions WHERE scenario_id=? ORDER BY started_at DESC LIMIT 30", (f["scenario_id"],))
    can_ev = auth.can(u, f"evidence:{f['team']}")
    evid = db.q("SELECT id, execution_id, type, mode, kind, sha256, created_at, flags_detected FROM evidence "
                "WHERE scenario_id=? ORDER BY created_at DESC LIMIT 30", (f["scenario_id"],)) if can_ev else []
    sc = catalog.BY_ID.get(f["scenario_id"], {})
    return {"finding": f, "history": hist, "executions": exes if can_ev else [], "evidence": evid,
            "scenario": {k: v for k, v in sc.items() if k != "runner"},
            "permissions": {"triage": auth.can(u, "triage"), "edit": auth.can(u, f"edit:{f['team']}"),
                            "retest": auth.can(u, f"retest:{f['team']}"), "evidence": can_ev}}


@router.patch("/findings/{fid}")
def patch_finding(fid: str, body: FindingPatch, request: Request):
    u = current(request)
    f = db.q1("SELECT * FROM findings WHERE id=?", (fid,))
    if not f:
        raise HTTPException(404, "Finding introuvable.")
    changes = {}
    if body.owner is not None or body.mitigation is not None:
        need(u, "triage")
        if body.owner is not None:
            changes["owner"] = body.owner.strip()[:80] or None
        if body.mitigation is not None:
            changes["mitigation"] = body.mitigation.strip()[:2000]
    if body.impact is not None or body.description is not None:
        need(u, f"edit:{f['team']}")  # une équipe ne modifie pas les findings d'une autre équipe
        if body.impact is not None:
            changes["impact"] = body.impact.strip()[:2000]
        if body.description is not None:
            changes["description"] = body.description.strip()[:4000]
    if not changes:
        raise HTTPException(422, "Aucune modification.")
    changes["updated_at"] = db.now()
    db.update("findings", "id", fid, changes)
    audit(u, "finding.update", fid, {k: v for k, v in changes.items() if k != "updated_at"}, _ip(request))
    return {"finding": db.q1("SELECT * FROM findings WHERE id=?", (fid,))}


@router.post("/findings/{fid}/transition")
def transition(fid: str, body: Transition, request: Request):
    u = current(request)
    need(u, "triage")
    try:
        f = engine.transition(fid, body.to, u["username"], body.note[:1000])
    except engine.WorkflowError as exc:
        raise HTTPException(409, str(exc))
    audit(u, "finding.transition", fid, {"to": body.to, "note": body.note[:200]}, _ip(request))
    return {"finding": f}


@router.post("/findings/{fid}/retest")
async def retest(fid: str, request: Request):
    u = current(request)
    f = db.q1("SELECT * FROM findings WHERE id=?", (fid,))
    if not f:
        raise HTTPException(404, "Finding introuvable.")
    need(u, f"retest:{f['team']}")
    if f["status"] != "RETEST_REQUIRED":
        raise HTTPException(409, "Le retest n'est possible qu'au statut RETEST_REQUIRED (après correction Blue Team).")
    res = await engine.execute(f["scenario_id"], "hardened", u["username"], kind="retest")
    if res["status"] != "completed":
        raise HTTPException(503, f"Retest impossible : {res['summary']}")
    audit(u, "finding.retest", fid, {"execution": res["id"], "outcome": res["outcome"]}, _ip(request))
    return {"execution": res, "finding": db.q1("SELECT * FROM findings WHERE id=?", (fid,))}


# ------------------------------------------------------------------ preuves, événements, incidents
@router.get("/evidence")
def evidence_list(request: Request, team: str = ""):
    u = current(request)
    teams = [team] if team else _visible(u)
    for t in teams:
        need(u, f"evidence:{t}")
    rows = db.q(f"SELECT id, execution_id, finding_id, team, scenario_id, component, type, sha256, flags_detected, "
                f"created_at, mode, kind FROM evidence WHERE team IN ({','.join('?' * len(teams))}) "
                f"ORDER BY created_at DESC LIMIT 500", tuple(teams)) if teams else []
    return {"evidence": rows}


@router.get("/evidence/{eid}")
def evidence(eid: str, request: Request):
    u = current(request)
    e = db.q1("SELECT * FROM evidence WHERE id=?", (eid,))
    if not e:
        raise HTTPException(404, "Preuve introuvable.")
    need(u, f"evidence:{e['team']}")
    return {"evidence": e, "integrity": "valid" if engine.verify_evidence(e) else "tampered"}


@router.get("/events")
def events(request: Request, limit: int = 50, team: str = "", severity: str = ""):
    current(request)
    where, args = [], []
    if team:
        where.append("team=?"); args.append(team)
    if severity:
        where.append("severity=?"); args.append(severity)
    sql = "SELECT * FROM security_events" + (" WHERE " + " AND ".join(where) if where else "")
    return {"events": db.q(sql + " ORDER BY at DESC LIMIT ?", (*args, max(1, min(limit, 500))))}


@router.get("/incidents")
def incidents(request: Request):
    current(request)
    out = []
    for i in db.q("SELECT * FROM incidents ORDER BY updated_at DESC"):
        exes = db.q("SELECT id, mode, kind, outcome, blocked_by, started_at FROM executions WHERE incident_id=? "
                    "ORDER BY started_at DESC LIMIT 20", (i["id"],))
        last = db.q1("SELECT content FROM evidence WHERE execution_id=?", (i["last_execution_id"],))
        stages = ((last or {}).get("content") or {}).get("artifact", {}).get("stages") if last else None
        out.append({**i, "executions": exes, "stages": stages})
    return {"incidents": out}


@router.get("/metrics")
def get_metrics(request: Request, since: float = 0):
    current(request)
    return metrics.overview(since or None)


@router.get("/controls")
def controls(request: Request):
    current(request)
    out = []
    for c in catalog.controls_dict():
        linked = [s["id"] for s in catalog.SCENARIOS if c["id"] in s["controls"]]
        last = db.q(f"SELECT scenario_id, outcome, blocked_by, started_at FROM executions WHERE mode='hardened' "
                    f"AND status='completed' AND scenario_id IN ({','.join('?' * len(linked))}) "
                    f"ORDER BY started_at DESC", tuple(linked)) if linked else []
        seen, latest = set(), []
        for e in last:
            if e["scenario_id"] not in seen:
                seen.add(e["scenario_id"])
                latest.append(e)
        validated = None
        if latest:
            validated = "pass" if all(e["outcome"] == "attack_blocked" for e in latest) else "fail"
        out.append({**c, "scenarios": linked, "validation": validated, "evidence_runs": len(latest)})
    return {"controls": out}


@router.get("/audit")
def audit_log(request: Request, limit: int = 200):
    u = current(request)
    need(u, "audit:read")
    return {"audit": db.q("SELECT * FROM audit_log ORDER BY at DESC LIMIT ?", (max(1, min(limit, 1000)),))}


@router.get("/reports/export")
def export(request: Request, team: str = "", severity: str = "", status: str = ""):
    u = current(request)
    need(u, "report:export")
    audit(u, "report.export", team or "global", {"severity": severity, "status": status}, _ip(request))
    html = reports.build(team or None, severity or None, status or None, u["username"])
    return HTMLResponse(html, headers={"Content-Disposition": "attachment; filename=shopnova-security-report.html"})


@router.get("/search")
def search(request: Request, q: str = ""):
    u = current(request)
    s = q.strip().lower()
    if len(s) < 2:
        return {"results": []}
    res = []
    for f in db.q("SELECT id, title, team, status, severity FROM findings"):
        if s in f"{f['id']} {f['title']}".lower():
            res.append({"type": "finding", "id": f["id"], "label": f["title"], "team": f["team"]})
    vis = set(_visible(u))
    for sc in catalog.SCENARIOS:
        if sc["team"] in vis and s in f"{sc['id']} {sc['title']} {sc['category']}".lower():
            res.append({"type": "scenario", "id": sc["id"], "label": sc["title"], "team": sc["team"]})
    for e in db.q("SELECT id, team, scenario_id FROM evidence ORDER BY created_at DESC LIMIT 300"):
        if e["team"] in vis and s in e["id"].lower():
            res.append({"type": "evidence", "id": e["id"], "label": e["scenario_id"], "team": e["team"]})
    return {"results": res[:20]}


# ------------------------------------------------------------------ outils spécifiques aux espaces d'équipe
async def _adhoc(u, team, component, label, mode, coro_result, observation, evidence_obj):
    """Exécution libre (bac à sable d'équipe) : tracée et prouvée, mais sans création automatique de finding."""
    exe_id = db.next_id("EXE", 6)
    now = db.now()
    evs = detection.analyze({**observation, "player_id": config.PLAYER_ID})
    db.insert("executions", {"id": exe_id, "scenario_id": f"{team}-ADHOC", "team": team, "component": component,
                             "mode": mode, "kind": "adhoc", "status": "completed", "outcome": None,
                             "detected": int(bool(evs)), "detection_ms": None, "started_at": now, "finished_at": now,
                             "duration_ms": 0, "username": u["username"], "summary": label})
    for e in evs:
        db.insert("security_events", {"at": now, "severity": e["severity"], "team": team, "component": component,
                                      "rule": e["rule"], "message": f"{e['name']} — {e['message']}",
                                      "execution_id": exe_id, "mode": mode})
    content = engine.redact({"label": label, "mode": mode, "artifact": evidence_obj, "detections": evs,
                             "executed_by": u["username"], "executed_at": now})
    evd = db.next_id("EVD", 6)
    db.insert("evidence", {"id": evd, "execution_id": exe_id, "finding_id": None, "team": team,
                           "scenario_id": f"{team}-ADHOC", "component": component, "type": "adhoc",
                           "content": content, "sha256": engine.evidence_hash(content),
                           "flags_detected": engine._flags_in(json.dumps(evidence_obj, default=str)),
                           "created_at": now, "mode": mode, "kind": "adhoc"})
    db.update("executions", "id", exe_id, {"evidence_id": evd})
    return {"execution_id": exe_id, "evidence_id": evd, "detections": evs, "result": engine.redact(coro_result)}


@router.get("/agent/tools")
async def agent_tools(request: Request, mode: str = "vulnerable"):
    u = current(request)
    need(u, "evidence:AGT")
    try:
        import agent
        return await agent.list_tools_raw(_mode(mode) == "hardened")
    except Exception as exc:
        raise HTTPException(503, f"Serveur MCP indisponible : {type(exc).__name__}")


@router.get("/agent/tool-calls")
def agent_tool_calls(request: Request, limit: int = 100):
    """Inspecteur des appels d'outils : appels extraits des preuves AGT (scénarios et tests libres)."""
    u = current(request)
    need(u, "evidence:AGT")
    rows = db.q("SELECT e.id, e.execution_id, e.finding_id, e.scenario_id, e.mode, e.kind, e.created_at, e.content, "
                "x.outcome, x.detected FROM evidence e JOIN executions x ON x.id = e.execution_id "
                "WHERE e.team='AGT' ORDER BY e.created_at DESC LIMIT ?", (max(1, min(limit, 500)),))
    calls = []
    for r in rows:
        art = (r["content"] or {}).get("artifact", {}) if isinstance(r["content"], dict) else {}
        traces = art.get("trace") if isinstance(art.get("trace"), list) else (
            [{"tool": art.get("tool"), "args": art.get("request") or art.get("args"), "result": art.get("response") or art.get("result")}]
            if art.get("tool") else [])
        for t in traces:
            res = t.get("result") if isinstance(t.get("result"), dict) else {}
            calls.append({"evidence_id": r["id"], "execution_id": r["execution_id"], "finding_id": r["finding_id"],
                          "scenario_id": r["scenario_id"], "mode": r["mode"], "kind": r["kind"], "at": r["created_at"],
                          "tool": t.get("tool"), "args": t.get("args"), "result": res,
                          "authorization": "denied" if "error" in res else "allowed",
                          "outcome": r["outcome"], "detected": bool(r["detected"]),
                          "detections": [d.get("rule") for d in (r["content"] or {}).get("detections", [])]})
    return {"calls": calls}


@router.post("/agent/tool-call")
async def agent_tool_call(body: ToolCall, request: Request):
    u = current(request)
    need(u, "run:AGT")
    allowed = {"get_customer", "get_order", "refund", "send_email", "remember_preference", "get_preferences"}
    if body.tool not in allowed:
        raise HTTPException(422, "Outil inconnu.")
    mode = _mode(body.mode)
    try:
        r = await runners._mcp(body.tool, body.args, mode == "hardened")
    except runners.Unavailable as exc:
        raise HTTPException(503, str(exc))
    extra = {}
    if body.tool in ("refund", "get_order") and str(body.args.get("order_id", "")).isdigit():
        o = runners._order(int(body.args["order_id"])) or {}
        extra = {"order_owner": o.get("customer_id"), "order_amount": o.get("amount")}
    trace = {"tool": body.tool, "args": body.args, "result": r, **extra}
    authorized = "error" not in r
    out = await _adhoc(u, "AGT", "MCP Server", f"Appel d'outil {body.tool}", mode, r, {"tool_trace": [trace]},
                       {"type": "tool_trace", **trace})
    if body.tool == "remember_preference" and authorized and body.args.get("customer_id") == config.PLAYER_ID:
        pass  # la préférence reste : action volontaire de l'équipe dans son bac à sable
    audit(u, "agent.tool_call", body.tool, {"mode": mode, "authorized": authorized}, _ip(request))
    return {**out, "authorization": "allowed" if authorized else "denied", "trace": engine.redact(trace)}


@router.get("/llm/config")
def llm_config(request: Request):
    u = current(request)
    need(u, "evidence:LLM")
    import orchestrator
    def h(s):
        return hashlib.sha256(s.encode()).hexdigest()[:16]
    vuln = orchestrator.VULNERABLE_SYSTEM_PROMPT
    return {"model": config.CHAT_MODEL, "endpoint": config.OLLAMA_HOST,
            "limits": {"vulnerable": {"max_input": None, "num_predict": None, "history": "illimité, rôles libres"},
                       "hardened": {"max_input": orchestrator.MAX_INPUT, "num_predict": 300,
                                    "history": f"{orchestrator.MAX_HISTORY} messages, user/assistant"}},
            "system_prompts": {
                "vulnerable": {"sha256_16": h(vuln), "contains_secret": "FLAG{" in vuln,
                               "preview": engine.redact(vuln)},
                "hardened": {"sha256_16": h(orchestrator.SECURE_SYSTEM_PROMPT),
                             "contains_secret": "FLAG{" in orchestrator.SECURE_SYSTEM_PROMPT,
                             "preview": orchestrator.SECURE_SYSTEM_PROMPT}},
            "filter_patterns": orchestrator.SUSPECT_PATTERNS}


@router.post("/llm/probe")
async def llm_probe(body: Probe, request: Request):
    u = current(request)
    need(u, "run:LLM")
    import orchestrator
    mode = _mode(body.mode)
    secure = mode == "hardened"
    msg = body.message[:20000]
    pre = orchestrator.preflight(msg, [], secure)
    answer, llm = None, "skipped"
    if pre["allowed"]:
        if orchestrator.llm_available():
            answer, llm = "".join(orchestrator.stream([], msg, secure)), "executed"
        else:
            llm = "unavailable"
    obs = {"input": msg, "output": answer or "", "controls": pre["controls"]}
    result = {"preflight": {k: v for k, v in pre.items() if k != "history"}, "llm": llm, "response": answer}
    label = f"Prompt testing · {body.category[:60]}" if body.category else "Prompt testing"
    out = await _adhoc(u, "LLM", "LLM", label, mode, result, obs,
                       {"type": "llm_transcript", "prompt": msg[:4000], "response": answer, "preflight": pre["controls"]})
    audit(u, "llm.probe", mode, {"length": len(msg), "llm": llm}, _ip(request))
    return out


@router.get("/rag/documents")
def rag_documents(request: Request):
    u = current(request)
    need(u, "evidence:RAG")
    docs = []
    for f in sorted((ROOT / "rag" / "docs").glob("*.txt")):
        raw = f.read_bytes()
        docs.append({"name": f.name, "collection": "faq", "source": "officiel (rag/docs)", "size": len(raw),
                     "sha256": hashlib.sha256(raw).hexdigest(), "validation": "documentation officielle",
                     "permissions": "lecture publique", "embedding": None, "excerpt": raw.decode("utf-8")[:160]})
    store_status, reviews = "unavailable", []
    try:
        import orchestrator
        st = orchestrator.get_store()
        indexed = {d["id"]: d for d in st.list_documents("faq")}
        for d in docs:
            d["embedding"] = "indexé" if Path(d["name"]).stem in indexed else "non indexé"
        for r in st.list_documents("reviews"):
            reviews.append({"id": r["id"], "text": r["text"][:200], "metadata": r["metadata"],
                            "sha256": hashlib.sha256(r["text"].encode()).hexdigest()})
        store_status = "available"
    except Exception as exc:
        store_status = f"unavailable ({type(exc).__name__})"
    return {"documents": docs, "reviews": reviews, "store": store_status}


@router.post("/rag/gateway")
async def rag_gateway(body: Gateway, request: Request):
    u = current(request)
    need(u, "run:RAG")
    import guards
    import ws4_model
    mode = _mode(body.mode)
    secure = mode == "hardened"
    g = guards.moderate_review(body.product[:200], body.author[:200], body.text[:10000], secure)
    snap = ws4_model.snapshot()
    try:
        ws4_model.load_model("official", secure=False)
        cls = ws4_model.classify(body.text[:10000], secure)
    finally:
        ws4_model.restore(snap)
    result = {"gateway": g, "moderation_model": cls, "indexed": False}
    obs = {"documents": [body.text, body.author], "controls": [{"control": g.get("control", "rag.ingestion_gateway"),
                                                                "decision": "pass" if g["accepted"] else "block"}]}
    out = await _adhoc(u, "RAG", "RAG Ingestion", "Document security test", mode, result, obs,
                       {"type": "pipeline_trace", "document": body.text[:2000], "author": body.author[:200],
                        "gateway": g, "moderation": cls})
    audit(u, "rag.gateway_test", mode, {"accepted": g["accepted"]}, _ip(request))
    return out


# ------------------------------------------------------------------ CTF (mise en correspondance, sans modification)
@router.get("/ctf/mapping")
def ctf_mapping(request: Request):
    current(request)
    m = {}
    for s in catalog.SCENARIOS:
        for c in s["legacy_challenges"]:
            m.setdefault(c, []).append(s["id"])
    return {"team": catalog.CTF_TEAM, "category": catalog.CTF_CATEGORY, "scenarios": m}


# ------------------------------------------------------------------ administration
@router.get("/users")
def users(request: Request):
    u = current(request)
    need(u, "admin")
    return {"users": [auth.public_user(x) | {"active": bool(x["active"])} for x in db.q("SELECT * FROM users")]}


@router.post("/admin/reset-activity")
def reset_activity(request: Request):
    u = current(request)
    need(u, "admin")
    db.wipe_activity()
    audit(u, "admin.reset_activity", "secops.db", ip=_ip(request))
    return {"ok": True}
