"""Moteur de tests de sécurité : exécution contrôlée, évaluation, détection, preuves, registre des vulnérabilités.

Cycle commun aux trois équipes :
  scénario -> exécution (mode vulnérable ou durci) -> évaluation -> détection -> preuve -> finding créé/mis à jour
  -> Blue Team (triage, mitigation) -> RETEST_REQUIRED -> retest par l'équipe responsable -> VERIFIED si l'attaque
  échoue réellement en mode durci, sinon retour en MITIGATION_IN_PROGRESS.
Un statut VERIFIED ne peut JAMAIS être posé à la main : seul un retest réussi le produit.
"""
import asyncio
import hashlib
import json
import re
import time
import traceback

import config

from . import catalog, db, detection, runners

_run_lock = asyncio.Lock()  # les exécuteurs restaurent l'état du lab : une exécution à la fois

FLAG_NAMES = [n for n in dir(config) if n.startswith("FLAG_")]


def _flags_in(text: str) -> list[str]:
    return sorted({n for n in FLAG_NAMES if getattr(config, n) and getattr(config, n) in text})


def redact(obj):
    """Les preuves ne doivent jamais exposer un secret : FLAG{...} -> FLAG{•••}. La présence est tracée à part."""
    s = json.dumps(obj, ensure_ascii=False, default=str)
    return json.loads(re.sub(r"FLAG\{[^}\"]*\}", "FLAG{•••}", s))


def evidence_hash(content) -> str:
    return hashlib.sha256(json.dumps(content, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def _event_rows(events, execution_id, scenario, mode, at):
    for e in events:
        db.insert("security_events", {"at": at, "severity": e["severity"], "team": scenario["team"],
                                      "component": scenario["component"], "rule": e["rule"],
                                      "message": f"{e['name']} — {e['message']}", "execution_id": execution_id,
                                      "mode": mode})


def _history(fid, user, frm, to, note):
    db.insert("finding_history", {"finding_id": fid, "at": db.now(), "username": user, "from_status": frm,
                                  "to_status": to, "note": note})


def _upsert_finding(sc: dict, exe_id: str, mode: str, kind: str, outcome: str, detected: bool, user: str) -> str | None:
    f = db.q1("SELECT * FROM findings WHERE scenario_id=?", (sc["id"],))
    now = db.now()
    succeeded = outcome == "attack_succeeded"
    if kind == "retest":
        if not f:
            return None
        if succeeded:
            db.update("findings", "id", f["id"], {"status": "MITIGATION_IN_PROGRESS", "retest_result": "fail",
                                                  "updated_at": now, "last_execution_id": exe_id})
            _history(f["id"], user, f["status"], "MITIGATION_IN_PROGRESS",
                     f"Retest {exe_id} : l'attaque réussit encore en mode durci. Correctif insuffisant.")
        else:
            db.update("findings", "id", f["id"], {"status": "VERIFIED", "retest_result": "pass", "updated_at": now,
                                                  "verified_at": now, "last_execution_id": exe_id})
            _history(f["id"], user, f["status"], "VERIFIED",
                     f"Retest {exe_id} : l'attaque est bloquée en mode durci. Correctif vérifié.")
        return f["id"]
    if not succeeded:
        if f:
            db.update("findings", "id", f["id"], {"updated_at": now, "last_execution_id": exe_id})
        return f["id"] if f else None
    if f:
        changes = {"updated_at": now, "last_execution_id": exe_id}
        if detected:
            changes["detection_status"] = "detected"
        if mode == "hardened" and f["status"] == "VERIFIED":
            changes.update(status="OPEN", retest_result="fail", verified_at=None)
            _history(f["id"], user, "VERIFIED", "OPEN", f"Régression : l'attaque réussit en mode durci ({exe_id}).")
        db.update("findings", "id", f["id"], changes)
        return f["id"]
    fid = db.next_id(sc["team"])
    db.insert("findings", {
        "id": fid, "team": sc["team"], "scenario_id": sc["id"], "category": sc["category"],
        "component": sc["component"], "title": sc["title"],
        "description": f"{sc['description']} Condition observée : {sc['success_condition']}",
        "severity": sc["severity"], "impact": sc["impact"], "status": "OPEN",
        "detection_status": "detected" if detected else "undetected", "owner": None,
        "mitigation": sc["mitigation"],
        "collaborating_teams": ["LLM", "AGT"] if sc.get("chain") else [],
        "refs": {"legacy_challenges": sc["legacy_challenges"], "vuln_refs": sc["vuln_refs"], "owasp": sc["owasp"],
                 "atlas": sc["atlas"], "controls": sc["controls"]},
        "retest_result": None, "created_at": now, "updated_at": now, "verified_at": None,
        "first_execution_id": exe_id, "last_execution_id": exe_id, "incident_id": None, "created_by": user})
    _history(fid, user, None, "OPEN", f"Créé automatiquement par l'exécution {exe_id} (mode {mode}).")
    return fid


def _upsert_incident(sc: dict, exe_id: str, stages: list, finding_id: str | None, outcome: str) -> str:
    inc = db.q1("SELECT * FROM incidents WHERE title=?", (sc["title"],))
    now = db.now()
    comps = [s["component"] for s in stages]
    status = "confirmed" if outcome == "attack_succeeded" else "blocked"
    if inc:
        db.update("incidents", "id", inc["id"], {"updated_at": now, "last_execution_id": exe_id, "status": status,
                                                 "components": comps, "finding_id": finding_id or inc["finding_id"]})
        iid = inc["id"]
    else:
        iid = db.next_id("XC")
        db.insert("incidents", {"id": iid, "title": sc["title"], "entry_team": sc["team"],
                                "entry_component": "RAG Ingestion", "components": comps,
                                "collaborating_teams": ["LLM", "AGT"], "status": status, "created_at": now,
                                "updated_at": now, "last_execution_id": exe_id, "finding_id": finding_id})
    if finding_id:
        db.update("findings", "id", finding_id, {"incident_id": iid})
    return iid


async def execute(scenario_id: str, mode: str, user: str, kind: str = "test") -> dict:
    sc = catalog.BY_ID[scenario_id]
    secure = mode == "hardened"
    if sc["benign"]:
        kind = "benign"
    async with _run_lock:
        exe_id = db.next_id("EXE", 6)
        started = time.time()
        status, result, err = "completed", None, None
        try:
            result = await runners.RUNNERS[sc["runner"]](secure)
        except runners.Unavailable as exc:
            status, err = "unavailable", str(exc)
        except Exception as exc:  # erreur interne : consignée côté serveur, message générique côté client
            traceback.print_exc()
            status, err = "error", f"{type(exc).__name__}: {exc}"[:300]
        events, detection_ms = [], None
        if result:
            events = detection.analyze({**result["observation"], "player_id": config.PLAYER_ID})
            if result["outcome"] == "attack_blocked" and result.get("blocked_by") and \
                    not any(e["rule"] == "DET-CTL-01" for e in events):
                events.append({"rule": "DET-CTL-01", "name": detection.RULES["DET-CTL-01"][0], "severity": "medium",
                               "message": f"Bloqué par {result['blocked_by']}."})
            detection_ms = int((time.time() - started) * 1000) if events else None
        finished = time.time()
        outcome = result["outcome"] if result else None
        detected = bool(events)
        row = {"id": exe_id, "scenario_id": sc["id"], "team": sc["team"], "component": sc["component"], "mode": mode,
               "kind": "chain" if sc.get("chain") and kind == "test" else kind, "status": status,
               "outcome": outcome, "detected": int(detected), "detection_ms": detection_ms, "started_at": started,
               "finished_at": finished, "duration_ms": int((finished - started) * 1000), "username": user,
               "summary": result["summary"] if result else err, "blocked_by": result.get("blocked_by") if result else None}
        db.insert("executions", row)
        if not result:
            return {**row, "finding_id": None, "evidence_id": None, "incident_id": None, "events": [], "stages": None}
        _event_rows(events, exe_id, sc, mode, finished)
        fid = None
        if not sc["benign"]:
            fid = _upsert_finding(sc, exe_id, mode, kind, outcome, detected, user)
        incident = None
        if sc.get("chain"):
            incident = _upsert_incident(sc, exe_id, result.get("stages") or [], fid, outcome)
        raw = {"scenario": sc["id"], "title": sc["title"], "mode": mode, "kind": row["kind"], "outcome": outcome,
               "summary": result["summary"], "artifact": result["evidence"], "detections": events,
               "blocked_by": result.get("blocked_by"), "executed_at": started, "executed_by": user}
        flags = _flags_in(json.dumps(raw, ensure_ascii=False, default=str))
        content = redact(raw)
        evd = db.next_id("EVD", 6)
        db.insert("evidence", {"id": evd, "execution_id": exe_id, "finding_id": fid, "team": sc["team"],
                               "scenario_id": sc["id"], "component": sc["component"],
                               "type": result["evidence"].get("type", "trace"), "content": content,
                               "sha256": evidence_hash(content), "flags_detected": flags, "created_at": finished,
                               "mode": mode, "kind": row["kind"]})
        db.update("executions", "id", exe_id, {"finding_id": fid, "evidence_id": evd, "incident_id": incident})
        row.update(finding_id=fid, evidence_id=evd, incident_id=incident)
        return {**row, "events": events, "stages": result.get("stages")}


def verify_evidence(e: dict) -> bool:
    return evidence_hash(e["content"]) == e["sha256"]


# ---------------------------------------------------------------- workflow de remédiation
TRANSITIONS = {
    "OPEN": {"ANALYZED"},
    "ANALYZED": {"MITIGATION_IN_PROGRESS", "OPEN"},
    "MITIGATION_IN_PROGRESS": {"FIXED", "ANALYZED"},
    "FIXED": {"RETEST_REQUIRED", "MITIGATION_IN_PROGRESS"},
    "RETEST_REQUIRED": {"MITIGATION_IN_PROGRESS"},
    "VERIFIED": set(),
}


class WorkflowError(Exception):
    pass


def transition(fid: str, to: str, user: str, note: str = "") -> dict:
    f = db.q1("SELECT * FROM findings WHERE id=?", (fid,))
    if not f:
        raise WorkflowError("Finding introuvable.")
    if to == "VERIFIED":
        raise WorkflowError("VERIFIED ne peut être obtenu que par un retest réussi en mode durci.")
    if to not in TRANSITIONS.get(f["status"], set()):
        raise WorkflowError(f"Transition {f['status']} → {to} non autorisée.")
    changes = {"status": to, "updated_at": db.now()}
    if to == "RETEST_REQUIRED":
        changes["retest_result"] = "pending"
    db.update("findings", "id", fid, changes)
    _history(fid, user, f["status"], to, note or None)
    return db.q1("SELECT * FROM findings WHERE id=?", (fid,))
