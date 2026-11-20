from starlette.testclient import TestClient

import server
from conftest import H, PW, client_as


def test_unauthenticated_access_is_refused():
    c = TestClient(server.app)
    assert c.get("/api/secops/auth/me").status_code == 401
    assert c.get("/api/secops/findings").status_code == 401


def test_wrong_password_and_rate_limit():
    c = TestClient(server.app)
    codes = [c.post("/api/secops/auth/login", json={"username": "ghost-user", "password": "x"}).status_code for _ in range(6)]
    assert codes[:5] == [401] * 5 and codes[5] == 429


def test_session_cookie_is_httponly_and_strict():
    c = TestClient(server.app)
    r = c.post("/api/secops/auth/login", json={"username": "blue", "password": PW})
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie


def test_csrf_header_required_for_writes():
    c = client_as("agent")
    r = c.post("/api/secops/scenarios/AGT-S01/run", json={"mode": "vulnerable"})
    assert r.status_code == 403


def test_team_cannot_run_or_read_other_team(fresh):
    c = client_as("llm")
    assert c.post("/api/secops/scenarios/AGT-S01/run", json={"mode": "vulnerable"}, headers=H).status_code == 403
    assert c.get("/api/secops/evidence?team=AGT").status_code == 403
    assert c.get("/api/secops/scenarios?team=RAG").status_code == 403
    assert c.get("/api/secops/audit").status_code == 403


def test_auditor_is_read_only(fresh):
    c = client_as("auditor")
    assert c.get("/api/secops/audit").status_code == 200
    assert c.post("/api/secops/campaign", json={"team": "AGT"}, headers=H).status_code == 403


def test_team_cannot_edit_other_team_finding(fresh):
    a = client_as("agent")
    a.post("/api/secops/scenarios/AGT-S02/run", json={"mode": "vulnerable"}, headers=H)
    fid = a.get("/api/secops/findings").json()["findings"][0]["id"]
    r = client_as("rag").patch(f"/api/secops/findings/{fid}", json={"impact": "x"}, headers=H)
    assert r.status_code == 403
    assert a.patch(f"/api/secops/findings/{fid}", json={"impact": "Impact précisé"}, headers=H).status_code == 200
    assert a.patch(f"/api/secops/findings/{fid}", json={"owner": "moi"}, headers=H).status_code == 403  # triage = Blue Team
