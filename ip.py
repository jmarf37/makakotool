import sys
import requests
from datetime import datetime, timezone
import os
from dotenv import load_dotenv
import ipaddress


load_dotenv(dotenv_path='APIKEYS.env')


VT_API = os.getenv('VT_API')
ABUSE_API = os.getenv('ABUSE_API')
ALIEN_API = os.getenv('ALIEN_API')
IPQ_API = os.getenv('IPQ_API')


URL_VIRUSTOTAL = 'https://www.virustotal.com/api/v3/ip_addresses/'
URL_ABUSEIPDB = 'https://api.abuseipdb.com/api/v2/check'
URL_ALIEN = 'https://otx.alienvault.com/api/v1/indicators/IPv4/'
URL_IPQ = 'https://www.ipqualityscore.com/api/json/ip/'


BLACKLIST_URL = "https://dist.s2grupo.es/blacklist/ieoel2ganfaxpu81q2k0u5d1u0jzh3m6ogqf8xfliwpxwnocve2famnuscjf6cb0i/IP_list.txt"


RDAP_ENDPOINTS = [
    ("ARIN",    "https://rdap.arin.net/registry/ip/"),
    ("RIPE",    "https://rdap.db.ripe.net/ip/"),
    ("APNIC",   "https://rdap.apnic.net/ip/"),
    ("LACNIC",  "https://rdap.lacnic.net/rdap/ip/"),
    ("AFRINIC", "https://rdap.afrinic.net/rdap/ip/"),
]

TIMEOUT = 15


_BLACKLIST_CACHE = {
    "loaded": False,
    "ip_set": set(),
    "error": None,
    "fetched_at": None,
}


def get_date_difference(timestamp_date):
    given_date = datetime.fromtimestamp(timestamp_date, tz=timezone.utc)
    current_date = datetime.now(tz=timezone.utc)
    time_difference = current_date - given_date
    years = time_difference.days // 365
    months = (time_difference.days % 365) // 30
    days = (time_difference.days % 365) % 30
    if years > 0:
        return f"{years} year{'s' if years > 1 else ''}"
    elif months > 0:
        return f"{months} month{'s' if months > 1 else ''}"
    else:
        return f"{days} day{'s' if days > 1 else ''}"


def validate_ip(ip_str: str) -> bool:
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False

def _load_blacklist_once():
    """
    Descarga y cachea la blacklist en memoria para búsquedas rápidas.
    Parsing robusto: líneas, espacios, y comentarios.
    """
    global _BLACKLIST_CACHE

    if _BLACKLIST_CACHE["loaded"]:
        return

    try:
        with requests.get(BLACKLIST_URL, timeout=TIMEOUT, stream=True) as r:
            if r.status_code != 200:
                _BLACKLIST_CACHE["error"] = f"HTTP {r.status_code}"
                _BLACKLIST_CACHE["loaded"] = True
                return

            ip_set = set()
            for raw_line in r.iter_lines(decode_unicode=True):
                if raw_line is None:
                    continue
                line = raw_line.strip()

                if not line:
                    continue

                
                if "#" in line:
                    line = line.split("#", 1)[0].strip()
                    if not line:
                        continue

                tokens = line.split()

                for token in tokens:
                    token = token.strip()
                    if not token:
                        continue
                    token = token.strip(",;")
                    if validate_ip(token):
                        ip_set.add(token)

            _BLACKLIST_CACHE["ip_set"] = ip_set
            _BLACKLIST_CACHE["loaded"] = True
            _BLACKLIST_CACHE["fetched_at"] = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
            _BLACKLIST_CACHE["error"] = None

    except requests.exceptions.RequestException as e:
        _BLACKLIST_CACHE["error"] = str(e)
        _BLACKLIST_CACHE["loaded"] = True


def analyze_ip_BLACKLIST(ip_address):
    """
    Devuelve estado de pertenencia a blacklist de S2Grupo.
    """
    _load_blacklist_once()

    if _BLACKLIST_CACHE["error"]:
        return {
            "Blacklist (S2Grupo)": "Error",
            "Blacklist Error": _BLACKLIST_CACHE["error"],
        }

    found = ip_address in _BLACKLIST_CACHE["ip_set"]
    return {
        "Blacklist (S2Grupo)": "Sí" if found else "No",
        "Blacklist Fuente": "S2Grupo IP_list.txt",
        "Blacklist Consultada": _BLACKLIST_CACHE["fetched_at"],
    }


def analyze_ip_VT(ip_address):
    headers = {'x-apikey': VT_API}
    response = requests.get(f"{URL_VIRUSTOTAL}{ip_address}", headers=headers, timeout=TIMEOUT)
    if response.status_code != 200:
        print(f"Failed to retrieve data for IP address {ip_address} from VirusTotal (HTTP {response.status_code})")
        return {}
    data = response.json().get('data', {}).get('attributes', {})
    last_analysis_stats = data.get('last_analysis_stats', {})
    last_analysis_date_timestamp = data.get('last_analysis_date')
    return {
        "Community Score": f"{last_analysis_stats.get('malicious', 0)} / {sum(last_analysis_stats.values())}",
        "Security Vendors Flagged": (
            f"{last_analysis_stats.get('malicious', 0)} security vendors flagged this IP address as malicious"
            if last_analysis_stats.get('malicious', 0) > 0 else "No security vendors flagged this IP address as malicious"
        ),
        "IP": ip_address,
        "Network": data.get('network'),
        "ISP": f"AS {data.get('asn')} ({data.get('as_owner')})",
        "Country": data.get('country'),
        "Region": data.get('regional_internet_registry'),
        "Continent": data.get('continent'),
        "Jarm hash": data.get('jarm'),
        "Last Analysis Date": get_date_difference(last_analysis_date_timestamp) if last_analysis_date_timestamp else None,
        "category": data.get('category'),
        "Reputation": data.get('reputation')
    }


def analyze_ip_IPQS(ip_address, strictness=1, fast=True, user_agent=None, user_language=None):
    if not IPQ_API:
        # opcional; si no la usas siempre, no aborta el script
        return {}

    url = f"{URL_IPQ}{IPQ_API}/{ip_address}"
    params = {
        "strictness": strictness,
        "fast": "true" if fast else "false",
        "user_agent": user_agent,
        "user_language": user_language,
        "allow_public_access_points": "true",
        "lighter_penalties": "true",
    }
    params = {k: v for k, v in params.items() if v is not None}

    try:
        response = requests.get(url, params=params, timeout=TIMEOUT)
        if response.status_code != 200:
            print(f"Failed to retrieve data for IP address {ip_address} from IPQualityScore (HTTP {response.status_code})")
            return {}
        data = response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error calling IPQualityScore for {ip_address}: {e}")
        return {}

    return {
        "Fraud Score": data.get("fraud_score"),
        "Proxy": data.get("proxy"),
        "TOR": data.get("tor"),
        "Recent Abuse": data.get("recent_abuse"),
        "ISP": data.get("ISP"),
        "Organization": data.get("organization") or data.get("Organization"),
        "ASN": data.get("ASN"),
        "Country Code": data.get("country_code"),
        "City": data.get("city"),
        "Region": data.get("region"),
    }


def analyze_ip_ABUSE(ip_address):
    querystring = {'ipAddress': ip_address, 'maxAgeInDays': '90'}
    headers = {'Accept': 'application/json', 'Key': ABUSE_API}
    response = requests.get(URL_ABUSEIPDB, headers=headers, params=querystring, timeout=TIMEOUT)
    if response.status_code != 200:
        print(f"Failed to retrieve data for IP address {ip_address} from AbuseIPDB (HTTP {response.status_code})")
        return {}
    data = response.json().get('data', {})

    is_whitelisted = bool(data.get('isWhitelisted'))
    whitelist_msg = f"{ip_address} is whitelisted." if is_whitelisted else f"{ip_address} is not whitelisted."

    return {
        "Whitelist": whitelist_msg,
        "Reports": f"This IP ({ip_address}) was reported {data.get('totalReports')} times.",
        "Confidence of abuse": f"{data.get('abuseConfidenceScore')}",
        "ISP": data.get('isp'),
        "Usage Type": data.get('usageType'),
        "Country": data.get('countryCode'),
        "Hostnames": ', '.join(data.get('hostnames', [])),
        "Domain Name": data.get('domain'),
        "Last Reported": data.get('lastReportedAt'),
        "TOR": data.get('isTor')
    }


def analyze_ip_ALIEN(ip_address):
    headers = {'X-OTX-API-KEY': ALIEN_API}
    response = requests.get(f"{URL_ALIEN}{ip_address}/general", headers=headers, timeout=TIMEOUT)
    if response.status_code != 200:
        print(f"Failed to retrieve data for IP address {ip_address} from AlienVault (HTTP {response.status_code})")
        return {}
    data = response.json()
    pulse_info = data.get('pulse_info', {})
    pulses = pulse_info.get('pulses', [])
    return {
        "IP": data.get('indicator'),
        "Pulse Info Count": pulse_info.get('count'),
        "Pulse Info IDs": [pulse.get('id') for pulse in pulses if pulse.get('id')],
        "Continent Code": data.get('continent_code'),
        "Country Code": data.get('country_code2'),
        "Latitude": data.get('latitude'),
        "Longitude": data.get('longitude'),
        "ASN": data.get('asn')
    }

def _vcard_extract(vcard_array):
    """
    vcardArray: ["vcard", [ ["fn",{}, "text","Org"], ["email",{}, "text","a@b"], ... ]]
    Devuelve dict con fields relevantes para SOC.
    """
    result = {
        "fn": None,
        "org": None,
        "emails": [],
        "phones": [],
        "addresses": [],
    }
    if not vcard_array or not isinstance(vcard_array, list) or len(vcard_array) < 2:
        return result

    items = vcard_array[1]
    if not isinstance(items, list):
        return result

    for item in items:
        if not isinstance(item, list) or len(item) < 4:
            continue
        key = item[0]
        value = item[3]

        if key == "fn" and isinstance(value, str):
            result["fn"] = value
        elif key == "org":
            if isinstance(value, str):
                result["org"] = value
            elif isinstance(value, list) and value:
                result["org"] = str(value[0])
        elif key == "email":
            if isinstance(value, str) and value not in result["emails"]:
                result["emails"].append(value)
        elif key == "tel":
            if isinstance(value, str) and value not in result["phones"]:
                result["phones"].append(value)
        elif key == "adr":
            if isinstance(value, list):
                addr = " ".join([str(x) for x in value if x])
            else:
                addr = str(value)
            if addr and addr not in result["addresses"]:
                result["addresses"].append(addr)

    return result


def _entity_roles(entity):
    roles = entity.get("roles", [])
    if not isinstance(roles, list):
        return []
    return [r.lower() for r in roles if isinstance(r, str)]


def _extract_entities_contacts(rdap_json):
    contacts = {
        "abuse": [],
        "technical": [],
        "administrative": [],
        "registrant": [],
        "other": [],
    }

    entities = rdap_json.get("entities", []) or []
    if not isinstance(entities, list):
        return contacts

    for ent in entities:
        if not isinstance(ent, dict):
            continue

        roles = _entity_roles(ent)
        v = _vcard_extract(ent.get("vcardArray"))
        contact = {
            "handle": ent.get("handle"),
            "roles": roles,
            "name": v.get("fn"),
            "org": v.get("org"),
            "emails": v.get("emails", []),
            "phones": v.get("phones", []),
            "addresses": v.get("addresses", []),
        }

        if "abuse" in roles:
            contacts["abuse"].append(contact)
        elif "technical" in roles:
            contacts["technical"].append(contact)
        elif "administrative" in roles or "admin" in roles:
            contacts["administrative"].append(contact)
        elif "registrant" in roles:
            contacts["registrant"].append(contact)
        else:
            contacts["other"].append(contact)

    return contacts


def _format_rdap_date(date_str: str):
    if not date_str or not isinstance(date_str, str):
        return date_str, None

    try:
        dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        now = datetime.now(timezone.utc)
        delta = now - dt

        days = delta.days
        if days < 0:
            return dt.strftime("%d/%m/%Y %H:%M:%S UTC"), "en el futuro"

        years = days // 365
        months = (days % 365) // 30

        if years > 0:
            ago = f"hace {years} año" if years == 1 else f"hace {years} años"
        elif months > 0:
            ago = f"hace {months} mes" if months == 1 else f"hace {months} meses"
        else:
            ago = f"hace {days} día" if days == 1 else f"hace {days} días"

        return dt.strftime("%d/%m/%Y %H:%M:%S UTC"), ago

    except Exception:
        return date_str, None


def _normalize_event_action(action: str) -> str:
    if not action:
        return "Evento"

    a = action.strip().lower()
    mapping = {
        "registration": "Registrado",
        "last changed": "Última modificación",
        "last update of rdap database": "Actualización BD RDAP",
        "transfer": "Transferido",
        "expiration": "Expira",
        "reinstantiation": "Reinstanciado",
        "deletion": "Eliminado",
    }
    return mapping.get(a, action)


def _events_summary(rdap_json, max_events=5):
    events = rdap_json.get("events", []) or []
    if not isinstance(events, list):
        return []

    out = []
    for e in events:
        if not isinstance(e, dict):
            continue

        action_raw = e.get("eventAction")
        date_raw = e.get("eventDate")

        if not action_raw and not date_raw:
            continue

        action = _normalize_event_action(action_raw)
        date_pretty, ago = _format_rdap_date(date_raw)

        epoch_placeholder = (isinstance(date_raw, str) and date_raw.startswith("1970-01-01"))

        if epoch_placeholder:
            out.append(f"{action}: {date_pretty} (placeholder / fecha no fiable)")
        elif ago:
            out.append(f"{action}: {date_pretty} ({ago})")
        else:
            out.append(f"{action}: {date_pretty}")

    return out[:max_events]


def _cidr_from_start_end(start, end):
    try:
        s = ipaddress.ip_address(start)
        e = ipaddress.ip_address(end)
        nets = list(ipaddress.summarize_address_range(s, e))
        if len(nets) == 1:
            return str(nets[0])
        return None
    except Exception:
        return None


def analyze_ip_RDAP_SOC(ip_address):
    headers = {"Accept": "application/rdap+json, application/json"}
    last_error = None

    for rir_name, base in RDAP_ENDPOINTS:
        url = f"{base}{ip_address}"
        try:
            r = requests.get(url, headers=headers, timeout=TIMEOUT)
            if r.status_code == 404:
                continue
            if r.status_code != 200:
                last_error = f"{rir_name} HTTP {r.status_code}"
                continue

            data = r.json()

            start = data.get("startAddress")
            end = data.get("endAddress")
            cidr = _cidr_from_start_end(start, end) if start and end else None

            handle = data.get("handle")
            name = data.get("name")
            country = data.get("country")
            ip_version = data.get("ipVersion")

            contacts = _extract_entities_contacts(data)

            owner = None
            for bucket in ("registrant", "other", "administrative", "technical", "abuse"):
                if contacts.get(bucket):
                    c = contacts[bucket][0]
                    owner = c.get("org") or c.get("name")
                    if owner:
                        break

            events = _events_summary(data)

            link = None
            links = data.get("links", [])
            if isinstance(links, list) and links:
                for l in links:
                    if isinstance(l, dict) and l.get("href"):
                        link = l["href"]
                        break

            return {
                "RIR": rir_name,
                "Handle": handle,
                "Name": name,
                "IP Version": ip_version,
                "Country": country,
                "Start Address": start,
                "End Address": end,
                "CIDR": cidr,
                "Owner (heuristic)": owner,
                "Events": events,
                "Reference": link,
                "RDAP Contacts": contacts,
            }

        except requests.exceptions.RequestException as e:
            last_error = f"{rir_name} request error: {e}"
            continue
        except ValueError:
            last_error = f"{rir_name} invalid JSON"
            continue

    if last_error:
        return {"RDAP Error": f"No RDAP provider returned data. Last error: {last_error}"}
    return {"RDAP Error": "No RDAP provider returned data (unknown error)."}


def _print_contacts_bucket(title, bucket):
    if not bucket:
        print(f"{title}: N/A")
        return
    print(f"{title}:")
    for c in bucket:
        line = []
        if c.get("org"):
            line.append(c["org"])
        elif c.get("name"):
            line.append(c["name"])
        if c.get("handle"):
            line.append(f"({c['handle']})")
        if c.get("emails"):
            line.append("emails=" + ",".join(c["emails"]))
        if c.get("phones"):
            line.append("tel=" + ",".join(c["phones"]))
        print("  - " + " | ".join(line))


def store_results_in_file(ip_address):
    vt_data = analyze_ip_VT(ip_address)
    abuse_data = analyze_ip_ABUSE(ip_address)
    alien_data = analyze_ip_ALIEN(ip_address)
    ipqs_data = analyze_ip_IPQS(ip_address)
    rdap_data = analyze_ip_RDAP_SOC(ip_address)
    blacklist_data = analyze_ip_BLACKLIST(ip_address)

    with open(f"{ip_address}_results.txt", "w", encoding="utf-8") as file:
        file.write("-------- Virustotal -----------\n")
        for key, value in vt_data.items():
            file.write(f"{key}: {value}\n")

        file.write("\n-------- AbuseIPDB -----------\n")
        for key, value in abuse_data.items():
            file.write(f"{key}: {value}\n")

        file.write("\n-------- AlienVault -----------\n")
        for key, value in alien_data.items():
            file.write(f"{key}: {value}\n")

        file.write("\n-------- IPQualityScore -----------\n")
        for key, value in ipqs_data.items():
            file.write(f"{key}: {value}\n")

        file.write("\n-------- RDAP SOC -----------\n")
        for key, value in rdap_data.items():
            if key == "RDAP Contacts" and isinstance(value, dict):
                file.write("RDAP Contacts:\n")
                for role, items in value.items():
                    file.write(f"  {role}:\n")
                    for c in items:
                        file.write(
                            f"    - handle={c.get('handle')} org={c.get('org')} name={c.get('name')} "
                            f"emails={c.get('emails')} phones={c.get('phones')}\n"
                        )
            else:
                file.write(f"{key}: {value}\n")

        file.write("\n-------- Blacklist (S2Grupo) -----------\n")
        for key, value in blacklist_data.items():
            file.write(f"{key}: {value}\n")


def print_results_to_console(ip_address):
    vt_data = analyze_ip_VT(ip_address)
    abuse_data = analyze_ip_ABUSE(ip_address)
    alien_data = analyze_ip_ALIEN(ip_address)
    ipqs_data = analyze_ip_IPQS(ip_address)
    rdap_data = analyze_ip_RDAP_SOC(ip_address)
    blacklist_data = analyze_ip_BLACKLIST(ip_address)

    print(f"\n\nAnálisis Reputacional ------> {ip_address}\n")
    print("-" * 106)
    print("Resultado:")
    print(f"Virustotal --> ({vt_data.get('Community Score', 'N/A')} VT)")
    print(f"AbuseIPDB  --> {abuse_data.get('Reports', 'N/A')} | Confidence {abuse_data.get('Confidence of abuse', 'N/A')}")
    print(f"AlienVault OTX--> {alien_data.get('Pulse Info Count', 'N/A')}")
    print(f"IPQualityScore --> Fraud Score {ipqs_data.get('Fraud Score', 'N/A')} | TOR {ipqs_data.get('TOR')}")
   
    if blacklist_data.get("Blacklist (S2Grupo)") == "Error":
        print(f"Blacklist S2Grupo (MISP)--> ERROR ({blacklist_data.get('Blacklist Error', 'N/A')})")
    else:
        print(f"Blacklist S2Grupo (MISP)--> {blacklist_data.get('Blacklist (S2Grupo)', 'N/A')}")
    print("-" * 106)

    print("\n######### Virustotal #########")
    for key, value in vt_data.items():
        print(f"{key}: {value}")

    print("\n######### AbuseIPDB #########")
    for key, value in abuse_data.items():
        print(f"{key}: {value}")

    print("\n######### AlienVault OTX #########")
    for key, value in alien_data.items():
        print(f"{key}: {value}")

    print("\n######### IPQualityScore #########")
    for key, value in ipqs_data.items():
        print(f"{key}: {value}")

    print("\n######### Registration Data Access Protocol (RDAP) #########")
    for key, value in rdap_data.items():
        if key in ("RDAP Contacts",):
            continue
        if key == "Events" and isinstance(value, list):
            print("Events:")
            for ev in value:
                print(f"  - {ev}")
            continue
        print(f"{key}: {value}")

    if isinstance(rdap_data, dict) and isinstance(rdap_data.get("RDAP Contacts"), dict):
        contacts = rdap_data["RDAP Contacts"]
        _print_contacts_bucket("Abuse", contacts.get("abuse"))
        _print_contacts_bucket("Technical", contacts.get("technical"))
        _print_contacts_bucket("Administrative", contacts.get("administrative"))
        _print_contacts_bucket("Registrant", contacts.get("registrant"))

    print("\n######### Blacklist (S2Grupo) #########")
    for key, value in blacklist_data.items():
        print(f"{key}: {value}")


def main():
    arguments = sys.argv[1:]
    if not arguments:
        print("Uso: python script.py <ip1> [ip2] ...")
        sys.exit(1)

    for ip_address in arguments:
        if not validate_ip(ip_address):
            print(f"IP inválida: {ip_address}")
            continue
        print_results_to_console(ip_address)
        print("\n====================================================\n")

#cambio para añadir resultados en la pantalla del navegador

from datetime import datetime, timezone


def _utc_now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def _dashline() -> str:
    return "-" * 106


def _as_str(v):
    return "None" if v is None else str(v)


def _vt_short(vt: dict) -> str:
    """
    Devuelve: (0 / 93 VT) a partir de Community Score: "0 / 93"
    """
    cs = vt.get("Community Score")
    if isinstance(cs, str) and "/" in cs:
        return f"({cs} VT)"
    # fallback: intenta construir algo razonable
    return "(None / None VT)"


def _vt_full_line(vt: dict) -> str:
    """
    Devuelve: "Community Score: 0 / 93"
    """
    cs = vt.get("Community Score")
    return f"Community Score: {_as_str(cs)}"


def _vt_vendors_line(vt: dict) -> str:
    sv = vt.get("Security Vendors Flagged")
    return f"Security Vendors Flagged: {_as_str(sv)}"


def _abuse_result_line(abuse: dict, ip_str: str) -> str:
    reports = abuse.get("Reports")
    conf = abuse.get("Confidence of abuse")
    # tu ejemplo: "This IP (...) was reported 0 times. | Confidence 0"
    return f"AbuseIPDB  --> {_as_str(reports)} | Confidence {_as_str(conf)}"


def _ipqs_result_line(ipqs: dict) -> str:
    fraud = ipqs.get("Fraud Score")
    tor = ipqs.get("TOR")
    return f"IPQualityScore --> Fraud Score {_as_str(fraud)} | TOR {_as_str(tor)}"


def _blacklist_result_line(bl: dict) -> str:
    return f"Blacklist S2Grupo (MISP)--> {_as_str(bl.get('Blacklist (S2Grupo)'))}"


def format_console_report(ip_str: str, results: dict) -> str:
    """
    Genera un reporte de texto replicando el formato 'consola' que has mostrado.
    results debe incluir: virustotal, abuseipdb, alienvault, ipqualityscore, rdap, blacklist
    """

    vt = results.get("virustotal") or {}
    abuse = results.get("abuseipdb") or {}
    alien = results.get("alienvault") or {}
    ipqs = results.get("ipqualityscore") or {}
    rdap = results.get("rdap") or {}
    bl = results.get("blacklist") or {}

    out = []
    # Cabecera
    out.append(f"Análisis Reputacional ------> {ip_str}")
    out.append("")
    out.append(_dashline())
    out.append("Resultado:")

    # Resumen “Resultado:” (si alguna API falla, lo dejamos reflejado)
    if "error" in vt:
        out.append(f"Virustotal --> ERROR: {vt['error']}")
    else:
        out.append(f"Virustotal --> {_vt_short(vt)}")

    if "error" in abuse:
        out.append(f"AbuseIPDB  --> ERROR: {abuse['error']}")
    else:
        out.append(_abuse_result_line(abuse, ip_str))

    if "error" in alien:
        out.append(f"AlienVault OTX--> ERROR: {alien['error']}")
    else:
        out.append(f"AlienVault OTX--> {_as_str(alien.get('Pulse Info Count'))}")

    if "error" in ipqs:
        out.append(f"IPQualityScore --> ERROR: {ipqs['error']}")
    else:
        out.append(_ipqs_result_line(ipqs))

    if "error" in bl:
        out.append(f"Blacklist S2Grupo (MISP)--> ERROR: {bl['error']}")
    else:
        out.append(_blacklist_result_line(bl))

    out.append(_dashline())
    out.append("")

    # ######### Virustotal #########
    out.append("######### Virustotal #########")
    if "error" in vt:
        out.append(f"ERROR: {vt['error']}")
    else:
        out.append(_vt_full_line(vt))
        out.append(_vt_vendors_line(vt))
        out.append(f"IP: {ip_str}")
        out.append(f"Network: {_as_str(vt.get('Network'))}")
        out.append(f"ISP: {_as_str(vt.get('ISP'))}")
        out.append(f"Country: {_as_str(vt.get('Country'))}")
        out.append(f"Region: {_as_str(vt.get('Region'))}")
        out.append(f"Continent: {_as_str(vt.get('Continent'))}")
        out.append(f"Jarm hash: {_as_str(vt.get('Jarm hash'))}")
        out.append(f"Last Analysis Date: {_as_str(vt.get('Last Analysis Date'))}")
        out.append(f"category: {_as_str(vt.get('category'))}")
        out.append(f"Reputation: {_as_str(vt.get('Reputation'))}")
    out.append("")

    # ######### AbuseIPDB #########
    out.append("######### AbuseIPDB #########")
    if "error" in abuse:
        out.append(f"ERROR: {abuse['error']}")
    else:
        out.append(f"Whitelist: {_as_str(abuse.get('Whitelist'))}")
        out.append(f"Reports: {_as_str(abuse.get('Reports'))}")
        out.append(f"Confidence of abuse: {_as_str(abuse.get('Confidence of abuse'))}")
        out.append(f"ISP: {_as_str(abuse.get('ISP'))}")
        out.append(f"Usage Type: {_as_str(abuse.get('Usage Type'))}")
        out.append(f"Country: {_as_str(abuse.get('Country'))}")
        out.append(f"Hostnames: {_as_str(abuse.get('Hostnames'))}")
        out.append(f"Domain Name: {_as_str(abuse.get('Domain Name'))}")
        out.append(f"Last Reported: {_as_str(abuse.get('Last Reported'))}")
        out.append(f"TOR: {_as_str(abuse.get('TOR'))}")
    out.append("")

    # ######### AlienVault OTX #########
    out.append("######### AlienVault OTX #########")
    if "error" in alien:
        out.append(f"ERROR: {alien['error']}")
    else:
        out.append(f"IP: {ip_str}")
        out.append(f"Pulse Info Count: {_as_str(alien.get('Pulse Info Count'))}")
        out.append(f"Pulse Info IDs: {_as_str(alien.get('Pulse Info IDs'))}")
        out.append(f"Continent Code: {_as_str(alien.get('Continent Code'))}")
        out.append(f"Country Code: {_as_str(alien.get('Country Code'))}")
        out.append(f"Latitude: {_as_str(alien.get('Latitude'))}")
        out.append(f"Longitude: {_as_str(alien.get('Longitude'))}")
        out.append(f"ASN: {_as_str(alien.get('ASN'))}")
    out.append("")

    # ######### IPQualityScore #########
    out.append("######### IPQualityScore #########")
    if "error" in ipqs:
        out.append(f"ERROR: {ipqs['error']}")
    else:
        out.append(f"Fraud Score: {_as_str(ipqs.get('Fraud Score'))}")
        out.append(f"Proxy: {_as_str(ipqs.get('Proxy'))}")
        out.append(f"TOR: {_as_str(ipqs.get('TOR'))}")
        out.append(f"Recent Abuse: {_as_str(ipqs.get('Recent Abuse'))}")
        out.append(f"ISP: {_as_str(ipqs.get('ISP'))}")
        out.append(f"Organization: {_as_str(ipqs.get('Organization'))}")
        out.append(f"ASN: {_as_str(ipqs.get('ASN'))}")
        out.append(f"Country Code: {_as_str(ipqs.get('Country Code'))}")
        out.append(f"City: {_as_str(ipqs.get('City'))}")
        out.append(f"Region: {_as_str(ipqs.get('Region'))}")
    out.append("")

    # ######### RDAP #########
    out.append("######### Registration Data Access Protocol (RDAP) #########")
    if "error" in rdap:
        out.append(f"ERROR: {rdap['error']}")
    else:
        # Campos principales (según tu ejemplo)
        out.append(f"RIR: {_as_str(rdap.get('RIR'))}")
        out.append(f"Handle: {_as_str(rdap.get('Handle'))}")
        out.append(f"Name: {_as_str(rdap.get('Name'))}")
        out.append(f"IP Version: {_as_str(rdap.get('IP Version'))}")
        out.append(f"Country: {_as_str(rdap.get('Country'))}")
        out.append(f"Start Address: {_as_str(rdap.get('Start Address'))}")
        out.append(f"End Address: {_as_str(rdap.get('End Address'))}")
        out.append(f"CIDR: {_as_str(rdap.get('CIDR'))}")
        out.append(f"Owner (heuristic): {_as_str(rdap.get('Owner (heuristic)'))}")

        # Events
        events = rdap.get("Events")
        if events is not None:
            out.append("Events:")
            # Tu script podría devolver lista de strings ya formateadas
            if isinstance(events, list):
                for ev in events:
                    out.append(f"  - {ev}")
            else:
                out.append(f"  - {_as_str(events)}")

        # Reference
        ref = rdap.get("Reference")
        if ref is not None:
            out.append(f"Reference: {_as_str(ref)}")

        # Abuse / Technical / Administrative / Registrant
        abuse_contacts = rdap.get("Abuse")
        if abuse_contacts is not None:
            out.append("Abuse:")
            if isinstance(abuse_contacts, list):
                for a in abuse_contacts:
                    out.append(f"  - {a}")
            else:
                out.append(f"  - {_as_str(abuse_contacts)}")

        tech_contacts = rdap.get("Technical")
        if tech_contacts is not None:
            out.append("Technical:")
            if isinstance(tech_contacts, list):
                for t in tech_contacts:
                    out.append(f"  - {t}")
            else:
                out.append(f"  - {_as_str(tech_contacts)}")

        admin = rdap.get("Administrative")
        if admin is not None:
            out.append(f"Administrative: {_as_str(admin)}")

        registrant = rdap.get("Registrant")
        if registrant is not None:
            out.append("Registrant:")
            if isinstance(registrant, list):
                for r in registrant:
                    out.append(f"  - {r}")
            else:
                out.append(f"  - {_as_str(registrant)}")

    out.append("")

    # ######### Blacklist #########
    out.append("######### Blacklist (S2Grupo) #########")
    if "error" in bl:
        out.append(f"ERROR: {bl['error']}")
    else:
        out.append(f"Blacklist (S2Grupo): {_as_str(bl.get('Blacklist (S2Grupo)'))}")
        out.append(f"Blacklist Fuente: {_as_str(bl.get('Blacklist Fuente'))}")
        out.append(f"Blacklist Consultada: {_utc_now_str()}")
    out.append("")
    out.append("====================================================")

    return "\n".join(out)





if __name__ == "__main__":
    main()
