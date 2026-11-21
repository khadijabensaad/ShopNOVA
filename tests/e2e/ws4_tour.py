"""Parcours d'interface WS4 (Playwright) : onglet « Model Security (WS4) » de l'espace RAG, thèmes sombre et clair.
Prérequis : serveur lancé (python tests/run_dev_server.py 8765), mot de passe par défaut.
Usage : python tests/e2e/ws4_tour.py — échoue en cas d'erreur JavaScript ou d'étape manquante."""
import asyncio
import os
import sys

from playwright.async_api import async_playwright

BASE = os.getenv("LAB_URL", "http://127.0.0.1:8765")
OUT = os.getenv("SHOTS", "screenshots")
os.makedirs(OUT, exist_ok=True)


async def login(page, user):
    await page.context.clear_cookies()
    await page.goto(BASE + "/")
    await page.wait_for_selector("#login-pass")
    await page.fill("#login-user", user)
    await page.fill("#login-pass", "ShopNova!2026")
    await page.click("button[type=submit]")
    await page.wait_for_selector(".page-title")
    await page.wait_for_timeout(500)


async def open_ws4(page):
    await page.goto(BASE + "/#/team/RAG")
    await page.wait_for_timeout(1800)
    await page.click("button.tab >> text=Model Security (WS4)")
    await page.wait_for_selector("text=AI Supply Chain Inventory", timeout=8000)
    await page.wait_for_timeout(600)


async def main():
    errors, checks = [], []
    async with async_playwright() as p:
        b = await p.chromium.launch(args=["--no-sandbox"])

        async def newpage(theme):
            ctx = await b.new_context(viewport={"width": 1440, "height": 900}, color_scheme=theme, accept_downloads=True)
            pg = await ctx.new_page()
            pg.on("console", lambda m: errors.append(f"{m.type}: {m.text}")
                  if m.type == "error" and "401" not in m.text and "503" not in m.text else None)
            pg.on("pageerror", lambda e: errors.append(f"pageerror: {e}"))
            return pg

        pg = await newpage("dark")
        await login(pg, "admin")
        await pg.request.post(BASE + "/api/secops/ws4/model/reset", headers={"X-Requested-With": "shopnova"})
        await login(pg, "rag")
        await open_ws4(pg)
        for title in ("Adversarial ML", "Model Supply Chain", "RAG & Vector Security", "Retrieval Inspector"):
            checks.append((title, await pg.locator(f"h2:has-text('{title}'), h3:has-text('{title}')").count() > 0))
        checks.append(("bouton Signer désactivé pour la Team RAG",
                       await pg.locator("button:has-text('Signer')").first.is_disabled()))
        await pg.screenshot(path=f"{OUT}/ws4_01_dark_top.png", full_page=True)
        # durci : import + analyse → accepté mais inactif ; activation refusée (non signé)
        await pg.locator(".seg").nth(0).locator("button", has_text="Durci").click()
        await pg.click("text=Importer et analyser")
        await pg.wait_for_selector("text=Accepté par le scanner", timeout=8000)
        await pg.click("button:has-text('Activer')")
        await pg.wait_for_selector("text=Non vérifié : activation refusée", timeout=8000)
        checks.append(("activation refusée sans signature", True))
        await pg.screenshot(path=f"{OUT}/ws4_02_refused.png", full_page=True)
        # admin signe (éditeur de confiance)
        await login(pg, "admin")
        await open_ws4(pg)
        await pg.click("button:has-text('Signer')")
        await pg.wait_for_selector("text=local-demo", timeout=8000)
        await login(pg, "rag")
        await open_ws4(pg)
        await pg.click("button:has-text('Vérifier')")
        await pg.wait_for_selector("text=Vérifié : activation autorisée", timeout=8000)
        checks.append(("vérification réussie après signature", True))
        # format interdit : Pickle importé par fichier → rejeté sans être chargé
        await pg.set_input_files("input[type=file]", "tests/fixtures/models/forbidden_format.pkl")
        await pg.locator(".seg").nth(0).locator("button", has_text="Durci").click()
        await pg.click("text=Importer et analyser")
        await pg.wait_for_selector("text=Rejeté par le scanner", timeout=8000)
        checks.append(("Pickle rejeté + détection", await pg.locator("text=DET-ML-02").count() > 0))
        await pg.screenshot(path=f"{OUT}/ws4_03_pickle_rejected.png", full_page=True)
        # inventaire + export
        async with pg.expect_download() as dl:
            await pg.click("text=Exporter (JSON CycloneDX)")
        d = await dl.value
        checks.append(("export AI-BOM", d.suggested_filename == "shopnova-ai-bom.cdx.json"))
        # inspecteur de récupération : ChromaDB absent ici → message « indisponible », aucun résultat simulé
        await pg.click("text=Inspecter la récupération")
        await pg.wait_for_timeout(1500)
        txt = await pg.locator("text=/indisponible|transmis au LLM/").count()
        checks.append(("inspecteur : résultat réel ou « indisponible »", txt > 0))
        await pg.screenshot(path=f"{OUT}/ws4_04_vector.png", full_page=True)
        # thème clair
        pl = await newpage("light")
        await login(pl, "rag")
        await open_ws4(pl)
        await pl.screenshot(path=f"{OUT}/ws4_05_light.png", full_page=True)
        # autre équipe : onglet absent et API refusée côté serveur
        await login(pl, "llm")
        await pl.goto(BASE + "/#/team/LLM")
        await pl.wait_for_timeout(1500)
        checks.append(("onglet WS4 absent pour la Team LLM", await pl.locator("button.tab >> text=Model Security (WS4)").count() == 0))
        r = await pl.request.get(BASE + "/api/secops/ws4/overview")
        checks.append(("API WS4 refusée à la Team LLM (403)", r.status == 403))
        await login(pg, "admin")
        await pg.request.post(BASE + "/api/secops/ws4/model/reset", headers={"X-Requested-With": "shopnova"})
        await b.close()
    for name, ok in checks:
        print(("OK    " if ok else "ÉCHEC ") + name)
    for e in errors:
        print("JS", e)
    return 0 if all(ok for _, ok in checks) and not errors else 1


async def guarded():
    try:
        return await main()
    except Exception as exc:
        print("ÉCHEC du parcours :", str(exc).splitlines()[0])
        return 1


if __name__ == "__main__":
    sys.exit(asyncio.run(guarded()))
