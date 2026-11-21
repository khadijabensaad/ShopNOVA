"""Serveur du lab ShopNova : API + interfaces web. Lancer : python server.py -> http://localhost:8000

  /          plateforme SecOps (AI Security Command Center, 3 équipes d'attaque, Blue Team) — authentifiée
  /ctf       interface CTF historique (inchangée)
  /shop      boutique « client » de Nova (inchangée)
  /api/...   API historiques du lab (cible volontairement vulnérable, inchangées)
  /api/secops/...  API de la plateforme (authentification + RBAC côté serveur)
"""
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
for _sub in ("agent", "data", "rag"):  # chemins explicites (la v1 dépendait de l'ordre des imports)
    if str(ROOT / _sub) not in sys.path:
        sys.path.append(str(ROOT / _sub))

import uvicorn  # noqa: E402
from fastapi import FastAPI, HTTPException, Request  # noqa: E402
from fastapi.responses import FileResponse, StreamingResponse  # noqa: E402
from fastapi.staticfiles import StaticFiles  # noqa: E402
from pydantic import BaseModel  # noqa: E402

import config  # noqa: E402
import ctf  # noqa: E402
import guards  # noqa: E402
import orchestrator  # noqa: E402
import ws4_model  # noqa: E402
from secops import api as secops_api  # noqa: E402
from secops import auth as secops_auth  # noqa: E402

STATIC = Path(__file__).parent / "static"
PLATFORM = STATIC / "platform"

app = FastAPI(title="ShopNOVA AI Security Lab")
app.include_router(ctf.router)
app.include_router(secops_api.router)
app.mount("/assets", StaticFiles(directory=str(PLATFORM / "assets")), name="assets")

CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; "
       "font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data:; connect-src 'self'; "
       "frame-ancestors 'none'; base-uri 'self'; form-action 'self'")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    """En-têtes de sécurité pour la plateforme (les pages historiques du lab ne sont pas modifiées)."""
    response = await call_next(request)
    path = request.url.path
    if path == "/" or path.startswith("/assets") or path.startswith("/api/secops"):
        response.headers["Content-Security-Policy"] = CSP
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
    if path.startswith("/api/secops"):
        response.headers["Cache-Control"] = "no-store"
    return response


secops_auth.ensure_demo_users()


class Chat(BaseModel):
    history: list = []  # V07 : l'historique et les rôles viennent du client, sans vérification (mode vulnérable)
    message: str


class Mode(BaseModel):
    secure: bool


class Review(BaseModel):
    product: str
    author: str = "Client anonyme"
    text: str


class Notice(BaseModel):
    text: str


class AgentChat(BaseModel):
    history: list = []
    message: str


class McpCall(BaseModel):
    tool: str
    args: dict = {}


class Ws4Op(BaseModel):
    op: str
    text: str = ""
    label: str = "sûr"


def _store():
    try:
        return orchestrator.get_store()
    except Exception as exc:
        raise HTTPException(503, "Module d'avis indisponible." if config.state["secure"] else f"Module d'avis indisponible : {exc}")


@app.get("/")
def index():
    return FileResponse(PLATFORM / "index.html")


@app.get("/ctf")
def legacy_ctf():
    """Interface CTF d'origine, conservée telle quelle (les défis et flags restent compatibles)."""
    return FileResponse(STATIC / "ctf.html")


@app.get("/shop")
def shop():
    return FileResponse(Path(__file__).parent / "static" / "index.html")


@app.get("/api/status")
def status():
    return {"model": config.CHAT_MODEL, "secure": config.state["secure"]}


@app.post("/api/mode")
def set_mode(m: Mode):
    config.state["secure"] = m.secure
    return status()


@app.post("/api/chat")
def chat(c: Chat):
    return StreamingResponse(orchestrator.stream(c.history, c.message), media_type="text/plain; charset=utf-8")


@app.post("/api/review")
def add_review(r: Review):
    """V05 : en mode vulnérable, aucune modération avant indexation (porte d'entrée de V06)."""
    g = guards.moderate_review(r.product, r.author, r.text, config.state["secure"])
    if not g["accepted"]:
        raise HTTPException(400, g["reason"])
    r = Review(product=g["product"], author=g["author"], text=g["text"])
    text = f"Avis sur {r.product} par {r.author} : {r.text}"
    # Provenance scellée (HMAC serveur) : la récupération en mode durci écarte tout document qui ne l'a pas.
    meta = orchestrator.vector_policy().provenance_metadata(
        "reviews", text, "api/review", {"product": r.product, "author": r.author, "source": "avis client"})
    _store().add_document("reviews", doc_id=str(uuid.uuid4()), text=text, metadata=meta)
    return {"ok": True}


NOTICE = guards.NOTICE


@app.get("/api/notice")
def get_notice():
    return {"text": guards.read_notice()}


@app.post("/api/notice")  # V16 : aucune authentification en mode vulnérable
def set_notice(n: Notice):
    r = guards.write_notice(n.text, config.state["secure"])
    if not r["ok"]:
        raise HTTPException(403, r["reason"])
    return get_notice()


@app.get("/api/reviews")
def list_reviews():
    """V11 : liste de tous les avis sans authentification (mode vulnérable)."""
    if not guards.reviews_listing_allowed(config.state["secure"]):
        raise HTTPException(403, "Authentification requise.")
    col = _store().collection("reviews")
    if col.count() == 0:
        return {"reviews": []}
    data = col.get()
    return {"reviews": [{"id": i, "text": t, "meta": m}
                        for i, t, m in zip(data["ids"], data["documents"], data["metadatas"])]}


def _agent_flags(result: dict, history: list) -> list[str]:
    """Vérifie, pour chaque attaque WS3 jouable en conversation libre, si ce tour de parole la valide
    (A2/A6 apparaissent déjà en clair dans la réponse : inutile de les revérifier ici)."""
    return [ctf.flag(c["id"]) for c in ctf.CHALLENGES
            if c["target"] in ("agent", "notice") and ctf.evaluate_agent(c, result, history, config.PLAYER_ID)]


@app.post("/api/agent/chat")
async def agent_chat(c: AgentChat):
    """Nova Agent, en dehors de tout défi noté : les mêmes outils, le même serveur MCP, en chat libre."""
    try:
        import agent
    except Exception as exc:
        raise HTTPException(503, f"Nova Agent indisponible : {exc}")
    result = await agent.run(c.history, c.message, config.state["secure"])
    return {**result, "secure": config.state["secure"], "derived_flags": _agent_flags(result, c.history)}


@app.post("/api/mcp/call")
async def mcp_call(c: McpCall):
    """Appel direct d'un outil MCP, sans passer par l'agent (même route que le défi A6)."""
    try:
        import agent
    except Exception as exc:
        raise HTTPException(503, f"Serveur MCP indisponible : {exc}")
    res = await agent.call_tool_raw(c.tool, c.args, config.state["secure"])
    return {"result": res, "secure": config.state["secure"]}


@app.post("/api/ws4")
def ws4_op(c: Ws4Op):
    """Le classificateur de modération, en dehors de tout défi noté."""
    ops = {"classify": lambda: ws4_model.classify(c.text, config.state["secure"]),
           "retrain": lambda: ws4_model.retrain(c.text, c.label, config.state["secure"]),
           "upload": lambda: ws4_model.upload_model(c.text, config.state["secure"]),
           "activate_official": lambda: ws4_model.load_model("official", config.state["secure"]),
           "activate_custom": lambda: ws4_model.load_model("custom", config.state["secure"])}
    fn = ops.get(c.op)
    if not fn:
        raise HTTPException(400, "Opération inconnue.")
    res = fn()
    flags = [ctf.flag(ch["id"]) for ch in ctf.CHALLENGES
             if c.op == "classify" and ch["ws"] == "WS4" and ctf.evaluate_ws4(ch, res, c.text)]
    return {**res, "secure": config.state["secure"], "derived_flags": flags}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8000)
