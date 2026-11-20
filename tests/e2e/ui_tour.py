"""Parcours d interface de bout en bout (Playwright) : toutes les pages, 2 thèmes, mobile, workflow de remédiation.
Prérequis : serveur lancé (python tests/run_dev_server.py 8765), campagne de référence exécutée, mot de passe par défaut.
Usage : python tests/e2e/ui_tour.py  — échoue en cas d erreur JavaScript."""
import asyncio, json
from playwright.async_api import async_playwright
import os, sys
BASE = os.getenv("LAB_URL", "http://127.0.0.1:8765"); OUT = os.getenv("SHOTS", "screenshots"); os.makedirs(OUT, exist_ok=True)
H = {"X-Requested-With": "shopnova"}
async def login(page, user):
    await page.context.clear_cookies(); await page.goto(BASE + "/"); await page.wait_for_selector("#login-pass")
    await page.fill("#login-user", user); await page.fill("#login-pass", "ShopNova!2026"); await page.click("button[type=submit]")
    await page.wait_for_selector(".page-title"); await page.wait_for_timeout(600)
async def go(page, hash, name, full=False, wait=1400):
    await page.goto(BASE + "/#" + hash); await page.wait_for_timeout(wait)
    await page.screenshot(path=f"{OUT}/{name}.png", full_page=full)
async def main():
    async with async_playwright() as p:
        b = await p.chromium.launch(args=["--no-sandbox"])
        errors = []
        async def newpage(theme):
            ctx = await b.new_context(viewport={"width": 1440, "height": 900}, color_scheme=theme)
            pg = await ctx.new_page()
            pg.on("console", lambda m: errors.append(f"{m.type}: {m.text}") if m.type == "error" and "401" not in m.text else None)
            pg.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))
            return pg
        pg = await newpage("dark")
        await login(pg, "admin")
        # chain runs
        await go(pg, "/cross", "x", wait=1200)
        await pg.click("text=Exécuter la chaîne (vulnérable)"); await pg.wait_for_timeout(6000)
        await pg.click("text=Rejouer (durci)"); await pg.wait_for_timeout(6000)
        await pg.screenshot(path=f"{OUT}/10_cross_dark.png", full_page=True)
        await go(pg, "/overview", "11_overview_dark", full=True, wait=2500)
        await go(pg, "/team/AGT", "12_agt_overview_dark", wait=2500)
        await pg.click("button.tab >> text=Scénarios"); await pg.wait_for_timeout(1200); await pg.screenshot(path=f"{OUT}/13_agt_scenarios.png")
        await pg.click("button.tab >> text=Tool Call Inspector"); await pg.wait_for_timeout(3000)
        await pg.click("text=Appeler l'outil"); await pg.wait_for_timeout(3000)
        await pg.screenshot(path=f"{OUT}/14_agt_console.png", full_page=True)
        await go(pg, "/team/LLM", "15_llm_overview", wait=2500)
        await pg.click("button.tab >> text=Prompt Testing"); await pg.wait_for_timeout(1200)
        await pg.click("text=Soumettre le test"); await pg.wait_for_timeout(2500)
        await pg.screenshot(path=f"{OUT}/16_llm_console.png", full_page=True)
        await go(pg, "/team/RAG", "17_rag_overview", wait=2500)
        await pg.click("button.tab >> text=Document Inspector"); await pg.wait_for_timeout(1200)
        await pg.click("text=Tester l'ingestion"); await pg.wait_for_timeout(2000)
        await pg.screenshot(path=f"{OUT}/18_rag_console.png", full_page=True)
        await go(pg, "/blue", "19_blue_inbox")
        await pg.click("button.tab >> text=Remediation Workflow"); await pg.wait_for_timeout(1000); await pg.screenshot(path=f"{OUT}/20_blue_board.png")
        await pg.click("button.tab >> text=Security Controls"); await pg.wait_for_timeout(1200); await pg.screenshot(path=f"{OUT}/21_blue_controls.png", full_page=True)
        await pg.click("button.tab >> text=Audit Log"); await pg.wait_for_timeout(1000); await pg.screenshot(path=f"{OUT}/22_audit.png")
        await go(pg, "/registry?f=AGT-001", "23_registry_drawer", wait=2000)
        await go(pg, "/evidence", "24_evidence")
        await pg.click("table.tbl tbody tr >> nth=0"); await pg.wait_for_timeout(1200); await pg.screenshot(path=f"{OUT}/25_evidence_modal.png")
        await go(pg, "/history", "26_history")
        await go(pg, "/ctf", "27_ctf")
        await go(pg, "/monitoring", "28_monitoring")
        await go(pg, "/reports", "29_reports", full=True)
        await go(pg, "/settings", "30_settings", full=True)
        # remediation workflow via API as blue then retest as agent
        r = await pg.request.post(BASE + "/api/secops/auth/login", data=json.dumps({"username": "blue", "password": "ShopNova!2026"}), headers={"Content-Type": "application/json"})
        for to in ["ANALYZED", "MITIGATION_IN_PROGRESS", "FIXED", "RETEST_REQUIRED"]:
            for fid in ["AGT-001", "AGT-005", "LLM-006"]:
                await pg.request.post(BASE + f"/api/secops/findings/{fid}/transition", data=json.dumps({"to": to}), headers={**H, "Content-Type": "application/json"})
        await pg.request.patch(BASE + "/api/secops/findings/AGT-001", data=json.dumps({"owner": "Khadija (Blue Team)"}), headers={**H, "Content-Type": "application/json"})
        await login(pg, "agent")
        await go(pg, "/registry?f=AGT-001", "31_agent_drawer_retest", wait=2000)
        await pg.click("text=Lancer le retest (mode durci)"); await pg.wait_for_timeout(4000)
        await pg.screenshot(path=f"{OUT}/32_after_retest.png")
        rr = await pg.request.post(BASE + "/api/secops/findings/AGT-005/retest", headers=H); print("AGT-005 retest", rr.status, (await rr.json())["finding"]["status"])
        await go(pg, "/team/LLM", "33_agent_forbidden_llm")
        await login(pg, "llm")
        rr = await pg.request.post(BASE + "/api/secops/findings/LLM-006/retest", headers=H); print("LLM-006 retest", rr.status, (await rr.json())["finding"]["status"])
        # light theme
        pl = await newpage("light")
        await login(pl, "blue")
        await go(pl, "/overview", "40_overview_light", full=True, wait=2500)
        await go(pl, "/blue", "41_blue_light")
        await go(pl, "/cross", "42_cross_light", wait=2000)
        await go(pl, "/registry", "43_registry_light")
        await login(pl, "rag")
        await go(pl, "/team/RAG", "44_rag_light", wait=2500)
        # mobile
        ctx = await b.new_context(viewport={"width": 390, "height": 844}, color_scheme="dark"); pm = await ctx.new_page()
        await login(pm, "admin"); await go(pm, "/overview", "50_mobile", wait=2000)
        print("ERRORS:", "\n".join(errors) or "none")
        await b.close()
        if errors:
            sys.exit(1)
asyncio.run(main())
