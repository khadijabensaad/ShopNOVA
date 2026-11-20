import json

from conftest import H, client_as


def test_agent_campaign_creates_findings_and_hardened_blocks(fresh):
    c = client_as("agent")
    r = c.post("/api/secops/campaign", json={"team": "AGT", "include_hardened": True}, headers=H).json()
    by = {(e["scenario_id"], e["mode"]): e for e in r["executions"]}
    assert by[("AGT-S01", "vulnerable")]["outcome"] == "attack_succeeded"
    assert by[("AGT-S01", "hardened")]["outcome"] == "attack_blocked"
    assert by[("AGT-S05", "hardened")]["outcome"] == "attack_succeeded"  # correctif volontairement imparfait (V17)
    assert by[("AGT-B01", "vulnerable")]["outcome"] == "benign_ok"
    f = c.get("/api/secops/findings").json()["findings"]
    ids = sorted(x["id"] for x in f)
    assert ids[0] == "AGT-001" and len(ids) == len({x["scenario_id"] for x in f})  # un finding par scénario


def test_evidence_is_hashed_and_secrets_masked(fresh):
    c = client_as("agent")
    e = c.post("/api/secops/scenarios/AGT-S01/run", json={"mode": "vulnerable"}, headers=H).json()
    ev = c.get(f"/api/secops/evidence/{e['evidence_id']}").json()
    assert ev["integrity"] == "valid"
    assert "FLAG_MCP_NOAUTH" in ev["evidence"]["flags_detected"]
    raw = json.dumps(ev["evidence"]["content"], ensure_ascii=False)
    assert "FLAG{•••}" in raw and "FLAG{mcp" not in raw


def test_rerun_does_not_duplicate_finding(fresh):
    c = client_as("agent")
    a = c.post("/api/secops/scenarios/AGT-S02/run", json={"mode": "vulnerable"}, headers=H).json()
    b = c.post("/api/secops/scenarios/AGT-S02/run", json={"mode": "vulnerable"}, headers=H).json()
    assert a["finding_id"] == b["finding_id"]


def _to_retest(blue, fid):
    for to in ("ANALYZED", "MITIGATION_IN_PROGRESS", "FIXED", "RETEST_REQUIRED"):
        assert blue.post(f"/api/secops/findings/{fid}/transition", json={"to": to}, headers=H).status_code == 200


def test_full_remediation_workflow_verified_only_by_retest(fresh):
    agent, blue = client_as("agent"), client_as("blue")
    fid = agent.post("/api/secops/scenarios/AGT-S04/run", json={"mode": "vulnerable"}, headers=H).json()["finding_id"]
    assert blue.post(f"/api/secops/findings/{fid}/transition", json={"to": "VERIFIED"}, headers=H).status_code == 409
    assert agent.post(f"/api/secops/findings/{fid}/retest", headers=H).status_code == 409  # trop tôt
    _to_retest(blue, fid)
    assert blue.post(f"/api/secops/findings/{fid}/retest", headers=H).status_code == 403  # retest = équipe responsable
    r = agent.post(f"/api/secops/findings/{fid}/retest", headers=H).json()
    assert r["execution"]["outcome"] == "attack_blocked" and r["finding"]["status"] == "VERIFIED"


def test_failed_retest_reopens_mitigation(fresh):
    agent, blue = client_as("agent"), client_as("blue")
    fid = agent.post("/api/secops/scenarios/AGT-S05/run", json={"mode": "vulnerable"}, headers=H).json()["finding_id"]
    _to_retest(blue, fid)
    r = agent.post(f"/api/secops/findings/{fid}/retest", headers=H).json()
    assert r["finding"]["status"] == "MITIGATION_IN_PROGRESS" and r["finding"]["retest_result"] == "fail"


def test_llm_and_rag_deterministic_scenarios(fresh):
    llm, rag = client_as("llm"), client_as("rag")
    out = {e["scenario_id"] + e["mode"][0]: e["outcome"] for e in
           llm.post("/api/secops/campaign", json={"team": "LLM", "include_hardened": True}, headers=H).json()["executions"]}
    assert out["LLM-S01v"] == "attack_succeeded" and out["LLM-S01h"] == "attack_blocked"
    assert out["LLM-S06h"] == "attack_succeeded"  # filtre par mots-clés contournable : non suffisant
    out = {e["scenario_id"] + e["mode"][0]: e["outcome"] for e in
           rag.post("/api/secops/campaign", json={"team": "RAG", "include_hardened": True}, headers=H).json()["executions"]}
    assert out["RAG-S07v"] == "attack_succeeded" and out["RAG-S07h"] == "attack_blocked"
    assert out["RAG-S03h"] == "attack_blocked" and out["RAG-B02v"] == "benign_ok"


def test_llm_scenarios_report_unavailable_without_model(fresh):
    import orchestrator
    if orchestrator.llm_available():
        return
    r = client_as("llm").post("/api/secops/scenarios/LLM-S07/run", json={"mode": "vulnerable"}, headers=H).json()
    assert r["status"] == "unavailable" and r["outcome"] is None and r["finding_id"] is None


def test_cross_component_chain(fresh):
    c = client_as("rag")
    v = c.post("/api/secops/scenarios/XC-S01/run", json={"mode": "vulnerable"}, headers=H).json()
    h = c.post("/api/secops/scenarios/XC-S01/run", json={"mode": "hardened"}, headers=H).json()
    assert v["outcome"] == "attack_succeeded" and h["outcome"] == "attack_blocked" and h["blocked_by"] == "CTL-AGT-05"
    assert {s["kind"] for s in v["stages"]} == {"confirmed", "simulated"}
    inc = c.get("/api/secops/incidents").json()["incidents"]
    assert len(inc) == 1 and inc[0]["entry_team"] == "RAG" and inc[0]["collaborating_teams"] == ["LLM", "AGT"]
    f = [x for x in c.get("/api/secops/findings").json()["findings"] if x["scenario_id"] == "XC-S01"]
    assert len(f) == 1 and f[0]["team"] == "RAG"


def test_metrics_empty_then_real(fresh):
    blue = client_as("blue")
    m = blue.get("/api/secops/metrics").json()
    assert m["has_data"] is False and m["global"]["attack_success_rate"] is None
    client_as("agent").post("/api/secops/campaign", json={"team": "AGT"}, headers=H)
    g = blue.get("/api/secops/metrics").json()["global"]
    assert g["attack_success_rate"] == 100.0 and g["false_positive_rate"] == 0.0 and g["total_vulnerabilities"] == 9


def test_report_export_has_no_secret(fresh):
    client_as("agent").post("/api/secops/campaign", json={"team": "AGT"}, headers=H)
    r = client_as("auditor").get("/api/secops/reports/export")
    assert r.status_code == 200 and "Rapport d'évaluation" in r.text and "FLAG{" not in r.text
    assert client_as("agent").get("/api/secops/reports/export").status_code == 403


def test_adhoc_tool_call_and_inspector(fresh):
    c = client_as("agent")
    r = c.post("/api/secops/agent/tool-call", json={"tool": "get_customer", "args": {"customer_id": 7}, "mode": "hardened"},
               headers=H).json()
    assert r["authorization"] == "denied"
    calls = c.get("/api/secops/agent/tool-calls").json()["calls"]
    assert calls and calls[0]["tool"] == "get_customer"
