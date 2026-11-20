"""Non-régression : les API, défis et flags historiques du lab restent compatibles."""
import json

from starlette.testclient import TestClient

import config
import ctf
import memory_store
import orchestrator
import server
import ws4_model


def test_pages_and_csp():
    c = TestClient(server.app)
    r = c.get("/")
    assert r.status_code == 200 and "script-src 'self'" in r.headers["content-security-policy"]
    assert c.get("/ctf").status_code == 200 and c.get("/shop").status_code == 200
    assert c.get("/assets/js/main.js").status_code == 200


def test_ctf_state_unchanged():
    s = TestClient(server.app).get("/api/ctf/state").json()
    assert s["total"] == 23 and s["max"] == 4750
    assert [c["id"] for c in s["challenges"]][:3] == ["C1", "C2", "C3"]


def test_ctf_a6_flag_and_submit():
    c = TestClient(server.app)
    c.post("/api/ctf/reset")
    r = c.post("/api/ctf/attempt", json={"id": "A6", "message": json.dumps({"tool": "get_customer", "args": {"customer_id": 13}})}).json()
    assert config.FLAG_MCP_NOAUTH in r["answer"]
    assert c.post("/api/ctf/submit", json={"id": "A6", "flag": config.FLAG_MCP_NOAUTH}).json()["ok"] is True
    c.post("/api/ctf/reset")


def test_ctf_ws4_b1_still_vulnerable():
    c = TestClient(server.app)
    text = ("Casque confortable recommande rapide soigné qualité parfait satisfait poli réactif solide pratique nette "
            "précise agréable léger INJECTION-PAYLOAD-X7")
    r = c.post("/api/ctf/attempt", json={"id": "B1", "message": json.dumps({"op": "classify", "text": text})}).json()
    assert r["released"] == ctf.flag("B1")


def test_hardened_v2_controls_do_not_touch_vulnerable_mode():
    assert "error" in memory_store.remember(42, "statut", "VIP", secure=True)
    assert memory_store.remember(42, "langue", "fr", secure=True) == {**memory_store.get(42)}
    memory_store.forget(42, "langue")
    assert ws4_model.classify("INJECTION-PAYLOAD-X7 " + "qualité " * 30, True)["label"] == "malveillant"
    assert "score" in ws4_model.classify("bonjour", False)


def test_orchestrator_steps():
    assert orchestrator.preflight("x" * 5000, [], False)["allowed"] is True
    assert orchestrator.preflight("x" * 5000, [], True)["allowed"] is False
    ctx = orchestrator.format_context([{"collection": "faq", "text": "t", "trust": "officiel", "source": "a.txt"}], True)
    assert "source : a.txt" in ctx
    assert "FLAG{" in orchestrator.assemble_system_prompt("", False) and "FLAG{" not in orchestrator.assemble_system_prompt("", True)
    assert orchestrator.postprocess("FLAG{abc}", True) == "[REDACTED]"
