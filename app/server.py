"""Serveur du lab ShopNova : API + interface web. Lancer : python server.py -> http://localhost:8000"""
import html
import uuid
from pathlib import Path

import uvicorn
from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel

import config
import ctf
import orchestrator
import ws4_model

app = FastAPI()
app.include_router(ctf.router)


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
    return FileResponse(Path(__file__).parent / "static" / "ctf.html")


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
    if config.state["secure"]:
        if any(orchestrator.input_looks_malicious(x) for x in (r.product, r.author, r.text)) or len(r.text) > 500:
            raise HTTPException(400, "Avis refusé par la modération.")
        r = Review(product=html.escape(r.product), author=html.escape(r.author), text=html.escape(r.text))
    text = f"Avis sur {r.product} par {r.author} : {r.text}"
    _store().add_document("reviews", doc_id=str(uuid.uuid4()), text=text,
                          metadata={"product": r.product, "author": r.author})
    return {"ok": True}


NOTICE = Path(__file__).resolve().parent.parent / "data" / "notice.txt"


@app.get("/api/notice")
def get_notice():
    if not NOTICE.exists():
        NOTICE.write_text("Politique du service client : rester poli, répondre dans les meilleurs délais.",
                          encoding="utf-8")
    return {"text": NOTICE.read_text(encoding="utf-8")}


@app.post("/api/notice")  # V16 : aucune authentification en mode vulnérable
def set_notice(n: Notice):
    if config.state["secure"]:
        raise HTTPException(403, "Modification de la note désactivée en mode sécurisé.")
    NOTICE.write_text(n.text[:2000], encoding="utf-8")
    return get_notice()


@app.get("/api/reviews")
def list_reviews():
    """V11 : liste de tous les avis sans authentification (mode vulnérable)."""
    if config.state["secure"]:
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
