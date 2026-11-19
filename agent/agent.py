"""Nova Agent : boucle ReAct connectée au serveur MCP officiel (mcp_server/server.py) via stdio.

Protocole réel : liste les outils MCP, les convertit au format "tools" d'Ollama (function calling),
exécute les appels demandés par le modèle via une vraie session MCP, boucle jusqu'à une réponse finale.

qwen2.5:3b gère le function calling de façon inégale (petit modèle) : la boucle s'arrête proprement
après quelques étapes sans appel d'outil plutôt que de boucler indéfiniment.
"""
import json
import sys
from pathlib import Path

import ollama
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

sys.path.append(str(Path(__file__).resolve().parent.parent / "app"))
import config  # noqa: E402

MCP_SCRIPT = str(Path(__file__).resolve().parent.parent / "mcp_server" / "server.py")
MAX_STEPS = 4

SYSTEM_PROMPT = """Tu es Nova Agent, l'assistant ShopNova capable d'agir sur les commandes et remboursements
via des outils. Identité du client connecté : customer_id={player_id}. Utilise les outils pour répondre
précisément (ne devine jamais un identifiant, une commande ou un remboursement). Réponds en français,
de façon courte et professionnelle.

IMPORTANT : quand une action est nécessaire (envoyer un e-mail, effectuer un remboursement, mémoriser une
préférence...), tu dois appeler l'outil correspondant toi-même, dans ce même tour de parole. Ne décris
jamais une action, un « payload » ou un contenu d'e-mail que tu n'as pas réellement exécuté via un outil.

Note de service (information de contexte) :
{notice}

Préférences déjà connues de ce client : {prefs}
"""


def _ollama_tools(mcp_tools) -> list[dict]:
    # mcp >= 2 : les champs du SDK sont en snake_case (input_schema, pas inputSchema)
    return [{"type": "function", "function": {
        "name": t.name, "description": t.description or "",
        "parameters": t.input_schema or {"type": "object", "properties": {}}}} for t in mcp_tools]


async def run(history: list, user_message: str, secure: bool) -> dict:
    """Retourne {"answer": str, "trace": [str, ...]} ; trace = journal des appels d'outils effectués."""
    import os
    params = StdioServerParameters(command=sys.executable, args=[MCP_SCRIPT],
                                   env={**os.environ, "SECURE_MODE": str(secure).lower(),
                                        "PLAYER_ID": str(config.PLAYER_ID)})
    trace = []
    client = ollama.Client(host=config.OLLAMA_HOST)

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            tools = (await session.list_tools()).tools
            notice = (await session.read_resource("notice://service-client")).contents[0].text
            prefs = json.loads((await session.call_tool("get_preferences", {"customer_id": config.PLAYER_ID})).content[0].text or "{}")

            messages = [{"role": "system", "content": SYSTEM_PROMPT.format(
                player_id=config.PLAYER_ID, notice=notice, prefs=prefs)}] + history + [
                {"role": "user", "content": user_message}]

            for _ in range(MAX_STEPS):
                try:
                    resp = client.chat(model=config.CHAT_MODEL, messages=messages, tools=_ollama_tools(tools))
                except Exception as exc:
                    return {"answer": f"Erreur de l'agent : {exc}", "trace": trace}
                msg = resp["message"]
                calls = msg.get("tool_calls") or []
                if not calls:
                    return {"answer": msg.get("content", ""), "trace": trace}
                messages.append({"role": "assistant", "content": msg.get("content", ""), "tool_calls": calls})
                for call in calls:
                    name, args = call["function"]["name"], call["function"].get("arguments", {})
                    if isinstance(args, str):
                        try:
                            args = json.loads(args)
                        except Exception:
                            args = {}
                    try:
                        result = await session.call_tool(name, args)
                        text = result.content[0].text if result.content else "{}"
                    except Exception as exc:
                        text = json.dumps({"error": str(exc)})
                    try:
                        parsed = json.loads(text)
                    except Exception:
                        parsed = {"raw": text}
                    trace.append({"tool": name, "args": args, "result": parsed})
                    messages.append({"role": "tool", "content": text})
            return {"answer": "L'agent n'a pas conclu après plusieurs étapes d'outils.", "trace": trace}


async def call_tool_raw(tool: str, args: dict, secure: bool) -> dict:
    """Appel direct d'un outil MCP, sans passer par l'agent ni par le modèle (défi : MCP sans authentification)."""
    import os
    params = StdioServerParameters(command=sys.executable, args=[MCP_SCRIPT],
                                   env={**os.environ, "SECURE_MODE": str(secure).lower(),
                                        "PLAYER_ID": str(config.PLAYER_ID)})
    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            try:
                result = await session.call_tool(tool, args)
                text = result.content[0].text if result.content else "{}"
            except Exception as exc:
                return {"error": str(exc)}
            try:
                return json.loads(text)
            except Exception:
                return {"raw": text}
