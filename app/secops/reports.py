"""Export HTML autonome du rapport d'évaluation (calculé à partir des enregistrements réels)."""
import datetime as dt
import html

from . import catalog, db, metrics

SEV_FR = {"critical": "Critique", "high": "Élevée", "medium": "Moyenne", "low": "Faible"}


def _fmt(v, unit=""):
    return "—" if v is None else f"{v}{unit}"


def build(team: str | None = None, severity: str | None = None, status: str | None = None, user: str = "") -> str:
    m = metrics.overview()
    fs = db.q("SELECT * FROM findings ORDER BY id")
    fs = [f for f in fs if (not team or f["team"] == team) and (not severity or f["severity"] == severity)
          and (not status or f["status"] == status)]
    g = m["teams"][team] if team else m["global"]
    e = html.escape
    rows = "".join(
        f"<tr><td class=mono>{e(f['id'])}</td><td>{e(catalog.TEAMS[f['team']]['short'])}</td><td>{e(f['category'])}</td>"
        f"<td>{e(f['title'])}</td><td><span class='sev {f['severity']}'>{SEV_FR[f['severity']]}</span></td>"
        f"<td class=mono>{e(f['status'])}</td><td>{e(f['retest_result'] or '—')}</td></tr>" for f in fs) or \
        "<tr><td colspan=7>Aucun finding pour ces filtres.</td></tr>"
    team_rows = "".join(
        f"<tr><td>{e(t['name'])}</td><td>{m['teams'][k]['tests']}</td><td>{m['teams'][k]['successful_attacks']}</td>"
        f"<td>{_fmt(m['teams'][k]['attack_success_rate'], ' %')}</td><td>{_fmt(m['teams'][k]['detection_rate'], ' %')}</td>"
        f"<td>{m['teams'][k]['open_vulnerabilities']}</td><td>{m['teams'][k]['fixed_vulnerabilities']}</td>"
        f"<td>{_fmt(m['teams'][k]['retest_pass_rate'], ' %')}</td><td>{_fmt(m['teams'][k]['residual_risk'], ' %')}</td></tr>"
        for k, t in catalog.TEAMS.items())
    most = m["most_vulnerable"]
    filt = ", ".join(x for x in [f"équipe {team}" if team else "", f"sévérité {severity}" if severity else "",
                                 f"statut {status}" if status else ""] if x) or "aucun"
    kpis = [("Vulnérabilités", g["total_vulnerabilities"]), ("Critiques/élevées ouvertes", g["critical_high"]),
            ("Taux de réussite des attaques", _fmt(g["attack_success_rate"], " %")),
            ("Taux de détection", _fmt(g["detection_rate"], " %")),
            ("Faux positifs", _fmt(g["false_positive_rate"], " %")),
            ("Taux de remédiation", _fmt(g["remediation_rate"], " %")),
            ("Retests réussis", _fmt(g["retest_pass_rate"], " %")), ("Risque résiduel", _fmt(g["residual_risk"], " %"))]
    kpi_html = "".join(f"<div class=k><b>{e(str(v))}</b><span>{e(k)}</span></div>" for k, v in kpis)
    return f"""<!doctype html><html lang=fr><head><meta charset=utf-8><title>Rapport ShopNOVA AI Security Lab</title>
<style>body{{font:14px/1.5 Inter,system-ui,sans-serif;color:#172033;margin:40px;max-width:1100px}}
h1{{font-family:'Space Grotesk',Inter,sans-serif;margin:0}}.sub{{color:#68758B}}.mono{{font-family:'JetBrains Mono',monospace;font-size:12px}}
table{{width:100%;border-collapse:collapse;margin:12px 0 28px}}th,td{{text-align:left;padding:7px 9px;border-bottom:1px solid #E4E9F2}}
th{{font-size:12px;text-transform:uppercase;letter-spacing:.04em;color:#68758B}}.grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;margin:20px 0}}
.k{{border:1px solid #E4E9F2;border-radius:10px;padding:12px}}.k b{{display:block;font-size:22px}}.k span{{color:#68758B;font-size:12px}}
.sev{{padding:2px 8px;border-radius:99px;font-size:12px}}.critical{{background:#fde6ea;color:#b4304a}}.high{{background:#fdf0dc;color:#9a6a10}}
.medium{{background:#e6f6f8;color:#056f7c}}.low{{background:#eef1f6;color:#4b5568}}.note{{background:#F5F7FC;border-radius:10px;padding:12px}}</style></head>
<body><h1>ShopNOVA AI Security Lab — Rapport d'évaluation</h1>
<p class=sub>Généré le {dt.datetime.now().strftime('%d/%m/%Y à %H:%M')} par {e(user)} · filtres : {e(filt)} ·
toutes les valeurs proviennent des exécutions enregistrées par la plateforme.</p>
<div class=grid>{kpi_html}</div>
<div class=note><b>Composant le plus exposé :</b> {e(f"{most['component']} (risque résiduel {most['residual_risk']} %)") if most else "pas encore de données"}.
Évaluation alignée sur une sélection d'exigences (OWASP Top 10 LLM 2025, MITRE ATLAS, NIST AI RMF, ISO/IEC 42001) — ce n'est pas une certification.</div>
<h2>Comparaison des trois équipes</h2><table><tr><th>Équipe</th><th>Tests</th><th>Réussies</th><th>Taux de réussite</th><th>Détection</th>
<th>Ouvertes</th><th>Vérifiées</th><th>Retests OK</th><th>Risque résiduel</th></tr>{team_rows}</table>
<h2>Registre des vulnérabilités</h2><table><tr><th>ID</th><th>Équipe</th><th>Catégorie</th><th>Titre</th><th>Sévérité</th>
<th>Statut</th><th>Retest</th></tr>{rows}</table>
<h2>Définitions</h2><ul>{''.join(f'<li><b>{e(k)}</b> : {e(v)}</li>' for k, v in metrics.DEFINITIONS.items())}</ul>
</body></html>"""
