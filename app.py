from flask import Flask, render_template, request, send_from_directory
from pathlib import Path
import re
import ip
from accounts import init_accounts, login_required, get_keys, SOURCES
from flask import g
import requests

app = Flask(
    __name__,
    static_folder="public",
    static_url_path="/static"
)

BASE_DIR = Path(__file__).resolve().parent

@app.route("/logo.png")
def logo():
    return send_from_directory(BASE_DIR / "templates", "logo.png")


def safe_call(func, ip_str, **kwargs):
    try:
        return func(ip_str, **kwargs)
    except requests.exceptions.Timeout:
        return {"error": "Tiempo de espera agotado"}
    except Exception:
        return {"error": "No se pudo consultar esta fuente"}


def _parse_vt_score_to_int(vt):
    """
    De 'Community Score' tipo '0 / 93' extrae el primer número (0).
    """
    cs = vt.get("Community Score")
    if isinstance(cs, str):
        m = re.search(r"(-?\d+)\s*/\s*\d+", cs)
        if m:
            try:
                return int(m.group(1))
            except ValueError:
                return None
    if isinstance(cs, (int, float)):
        return int(cs)
    return None


def _parse_vt_flagged_vendors_count(vt):
    sv = vt.get("Security Vendors Flagged")
    if isinstance(sv, str):
        m = re.search(r"(\d+)", sv)
        if m:
            try:
                return int(m.group(1))
            except ValueError:
                return None
    if isinstance(sv, (int, float)):
        return int(sv)
    return None


def _abuse_reports_count(abuse):
    rep = abuse.get("Reports")
    if isinstance(rep, str):
        m = re.search(r"reported\s+(\d+)\s+times", rep, flags=re.IGNORECASE)
        if m:
            try:
                return int(m.group(1))
            except ValueError:
                return None
    if isinstance(rep, (int, float)):
        return int(rep)
    return None


def _to_boolish(v):
    if isinstance(v, bool):
        return v
    if v is None:
        return False
    if isinstance(v, (int, float)):
        return v != 0
    s = str(v).strip().lower()
    return s in {"sí", "si", "yes", "true", "1", "y"}


def analyze_one(ip_str, keys):
    vt = safe_call(ip.analyze_ip_VT, ip_str, api_key=keys.get("VT_API"))
    abuse = safe_call(ip.analyze_ip_ABUSE, ip_str, api_key=keys.get("ABUSE_API"))
    alien = safe_call(ip.analyze_ip_ALIEN, ip_str, api_key=keys.get("ALIEN_API"))
    ipqs = safe_call(ip.analyze_ip_IPQS, ip_str, api_key=keys.get("IPQ_API"))
    rdap = safe_call(ip.analyze_ip_RDAP_SOC, ip_str)
    bl = safe_call(ip.analyze_ip_BLACKLIST, ip_str)

    vt_score = None if "error" in vt else _parse_vt_score_to_int(vt)
    vt_vendors_count = None if "error" in vt else _parse_vt_flagged_vendors_count(vt)
    vt_vendors_text = None if "error" in vt else vt.get("Security Vendors Flagged")

    abuse_report_count = None if "error" in abuse else _abuse_reports_count(abuse)
    alien_pulses = None if "error" in alien else alien.get("Pulse Info Count")
    ipqs_tor = None if "error" in ipqs else ipqs.get("TOR")

    flags = {
        # 1) VT score > 1
        "vt_score_red": (vt_score is not None and vt_score > 0),

        # 2) Vendors flagged > 1 y texto contiene frase
        "vt_vendors_red": (
            vt_vendors_count is not None
            and vt_vendors_count > 0
            and isinstance(vt_vendors_text, str)
            and "security vendors flagged this ip address as malicious"
            in vt_vendors_text.lower()
        ),

        # 3) Abuse reports > 10
        "abuse_reports_red": (
            abuse_report_count is not None and abuse_report_count > 10
        ),

        # 4) Alien pulses > 0
        "alien_pulses_red": (
            isinstance(alien_pulses, (int, float)) and int(alien_pulses) > 0
        ),

        # 5) IPQS TOR == sí/true
        "ipqs_tor_red": _to_boolish(ipqs_tor),
    }

    summary = {
        "Virustotal Community Score": vt.get("Community Score"),
        "Security Vendors Flagged": vt.get("Security Vendors Flagged"),
        "AbuseIPDB Reports": abuse.get("Reports"),
        "AbuseIPDB Confidence": abuse.get("Confidence of abuse"),
        "AlienVault Pulses": alien.get("Pulse Info Count"),
        "IPQS TOR": ipqs.get("TOR"),
        "IPQS Fraud Score": ipqs.get("Fraud Score"),
        "Blacklist S2Grupo": bl.get("Blacklist (S2Grupo)"),
        "RDAP Owner (heuristic)": rdap.get("Owner (heuristic)"),
        "Country": abuse.get("Country"),
    }

    report_text = ip.format_console_report(
        ip_str,
        {
            "virustotal": vt,
            "abuseipdb": abuse,
            "alienvault": alien,
            "ipqualityscore": ipqs,
            "rdap": rdap,
            "blacklist": bl,
        },
    )

    return {
        "ip": ip_str,
        "summary": summary,
        "flags": flags,
        "report_text": report_text,
    }


@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    results = []
    errors = []
    keys = get_keys(g.user)

    if request.method == "POST":
        raw = request.form.get("ips", "") or ""
        candidates = raw.replace(",", " ").replace("\t", " ").split()

        seen = set()
        ips = []
        for c in candidates:
            if c not in seen:
                seen.add(c)
                ips.append(c)

        if len(ips) > 5:
            errors.append("Introduce un máximo de 5 IP por consulta.")
            ips = []

        for ip_str in ips:
            if not ip.validate_ip(ip_str):
                errors.append("IP inválida: {}".format(ip_str))
                continue
            try:
                results.append(analyze_one(ip_str, keys))
            except Exception:
                errors.append("No se pudo completar el análisis de {}.".format(ip_str))

    return render_template("index.html", results=results, errors=errors, missing_sources=[label for key, label in SOURCES.items() if not keys.get(key)])


init_accounts(app)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
