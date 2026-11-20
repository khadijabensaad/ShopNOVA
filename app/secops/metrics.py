"""Indicateurs calculés UNIQUEMENT à partir des enregistrements réels (exécutions, findings, événements).

Quand une valeur ne peut pas être calculée (aucune donnée), elle vaut None : l'interface affiche alors un état
vide explicite plutôt qu'un chiffre inventé. Les définitions sont renvoyées avec les valeurs (transparence).
"""
from collections import Counter, defaultdict

from . import catalog, db

DEFINITIONS = {
    "total_vulnerabilities": "Nombre de findings dans le registre partagé.",
    "critical_high": "Findings critiques ou élevés non vérifiés.",
    "attack_success_rate": "Attaques réussies / attaques exécutées (mode vulnérable, tests initiaux).",
    "hardened_success_rate": "Attaques réussies / attaques exécutées en mode durci (tests + retests).",
    "detection_rate": "Attaques détectées par la surveillance / attaques exécutées (tous modes).",
    "false_positive_rate": "Exécutions de trafic légitime ayant déclenché une alerte / exécutions légitimes.",
    "remediation_rate": "Findings VERIFIED / findings.",
    "retest_pass_rate": "Retests réussis (attaque bloquée) / retests exécutés.",
    "mttd_ms": "Délai moyen entre le début d'une attaque et sa première détection (ms).",
    "mttr_h": "Délai moyen entre la création d'un finding et sa vérification (heures).",
    "residual_risk": "Somme des poids de sévérité des findings non vérifiés / somme totale × 100 "
                     "(critique 10, élevé 7, moyen 4, faible 1).",
}


def _rate(num, den):
    return round(100.0 * num / den, 1) if den else None


def _team_metrics(team: str | None, ex: list[dict], fs: list[dict]) -> dict:
    ex = [e for e in ex if team is None or e["team"] == team]
    fs = [f for f in fs if team is None or f["team"] == team]
    attacks = [e for e in ex if e["status"] == "completed" and e["kind"] in ("test", "retest", "chain")]
    vuln_tests = [e for e in attacks if e["mode"] == "vulnerable" and e["kind"] in ("test", "chain")]
    hard = [e for e in attacks if e["mode"] == "hardened"]
    retests = [e for e in attacks if e["kind"] == "retest"]
    benign = [e for e in ex if e["status"] == "completed" and e["kind"] == "benign"]
    detected = [e for e in attacks if e["detected"]]
    open_f = [f for f in fs if f["status"] != "VERIFIED"]
    verified = [f for f in fs if f["status"] == "VERIFIED"]
    w_all = sum(catalog.SEVERITY_WEIGHT[f["severity"]] for f in fs)
    w_open = sum(catalog.SEVERITY_WEIGHT[f["severity"]] for f in open_f)
    mttr = [(f["verified_at"] - f["created_at"]) / 3600 for f in verified if f["verified_at"]]
    mttd = [e["detection_ms"] for e in detected if e["detection_ms"] is not None]
    retest_executions = len(retests)
    return {
        "tests": len(attacks), "unavailable": len([e for e in ex if e["status"] == "unavailable"]),
        "successful_attacks": len([e for e in attacks if e["outcome"] == "attack_succeeded"]),
        "attack_success_rate": _rate(len([e for e in vuln_tests if e["outcome"] == "attack_succeeded"]),
                                     len(vuln_tests)),
        "hardened_success_rate": _rate(len([e for e in hard if e["outcome"] == "attack_succeeded"]), len(hard)),
        "detection_rate": _rate(len(detected), len(attacks)),
        "false_positive_rate": _rate(len([e for e in benign if e["detected"]]), len(benign)),
        "benign_runs": len(benign),
        "total_vulnerabilities": len(fs), "open_vulnerabilities": len(open_f),
        "critical_high": len([f for f in open_f if f["severity"] in ("critical", "high")]),
        "fixed_vulnerabilities": len(verified),
        "remediation_rate": _rate(len(verified), len(fs)),
        "retests": retest_executions,
        "retest_pass_rate": _rate(len([e for e in retests if e["outcome"] == "attack_blocked"]), retest_executions),
        "mttd_ms": round(sum(mttd) / len(mttd)) if mttd else None,
        "mttr_h": round(sum(mttr) / len(mttr), 2) if mttr else None,
        "residual_risk": round(100.0 * w_open / w_all, 1) if w_all else None,
        "retest_status": ("aucun" if not retests else
                          f"{len([e for e in retests if e['outcome'] == 'attack_blocked'])}/{retest_executions} réussis"),
        "severity": dict(Counter(f["severity"] for f in fs)),
        "status": dict(Counter(f["status"] for f in fs)),
    }


def overview(since: float | None = None) -> dict:
    """since : horodatage (s) — ne retient que l'activité postérieure (sélecteur de période du tableau de bord)."""
    ex = db.q("SELECT * FROM executions WHERE started_at >= ? ORDER BY started_at", (since or 0,))
    fs = db.q("SELECT * FROM findings WHERE updated_at >= ?", (since or 0,))
    glob = _team_metrics(None, ex, fs)
    teams = {t: _team_metrics(t, ex, fs) for t in catalog.TEAMS}
    ranked = sorted(((t, m) for t, m in teams.items() if m["total_vulnerabilities"]),
                    key=lambda x: (x[1]["residual_risk"] or 0, x[1]["critical_high"], x[1]["attack_success_rate"] or 0),
                    reverse=True)
    most = None
    if ranked:
        t, m = ranked[0]
        most = {"team": t, "component": catalog.TEAMS[t]["component"], "residual_risk": m["residual_risk"],
                "critical_high": m["critical_high"], "attack_success_rate": m["attack_success_rate"],
                "basis": "Classement par risque résiduel, puis findings critiques/élevés ouverts, puis taux de réussite."}
    # séries temporelles (par jour) et distribution par catégorie
    by_day = defaultdict(lambda: {"succeeded": 0, "blocked": 0})
    for e in ex:
        if e["status"] != "completed" or e["kind"] == "benign":
            continue
        import datetime as _dt
        day = _dt.datetime.fromtimestamp(e["started_at"]).strftime("%Y-%m-%d")
        by_day[day]["succeeded" if e["outcome"] == "attack_succeeded" else "blocked"] += 1
    categories = Counter((f["team"], f["category"]) for f in fs)
    heat = defaultdict(lambda: defaultdict(int))
    for f in fs:
        if f["status"] != "VERIFIED":
            heat[f["team"]][f["severity"]] += 1
    return {"global": glob, "teams": teams, "most_vulnerable": most, "definitions": DEFINITIONS,
            "timeline": [{"day": d, **v} for d, v in sorted(by_day.items())],
            "categories": [{"team": t, "category": c, "count": n} for (t, c), n in categories.most_common()],
            "heatmap": {t: dict(v) for t, v in heat.items()},
            "has_data": bool(ex)}
