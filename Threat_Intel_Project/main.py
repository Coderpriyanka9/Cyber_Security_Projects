import requests, pandas as pd, json, time
from config import THREAT_FEED_URL, API_KEY, DB_PATH, REPORT_FILE
from database import init_db, store_records
from ipwhois import IPWhois
import whois

# ---------------------- FETCH ----------------------
def fetch_threat_data():
    headers = {"X-OTX-API-KEY": API_KEY}
    try:
        print("[+] Fetching threat intelligence data...")
        r = requests.get(THREAT_FEED_URL, headers=headers, timeout=20)
        r.raise_for_status()
        data = r.json().get("results", [])
        return data
    except Exception as e:
        print(f"[ERROR] Failed to fetch data: {e}")
        return []

# ---------------------- NORMALIZE ----------------------
def normalize_data(raw_data):
    normalized = []
    for pulse in raw_data:
        for ind in pulse.get("indicators", []):
            normalized.append({
                "pulse_name": pulse.get("name"),
                "ioc": ind.get("indicator") or ind.get("value"),
                "type": ind.get("type") or "unknown"
            })
    return normalized

# ---------------------- ENRICH ----------------------
def enrich_data(normalized):
    enriched = []
    for i in normalized:
        enrichment = {}
        risk = 10

        # WHOIS / GeoIP enrichment
        try:
            if i["type"] in ["domain", "fqdn"]:
                w = whois.whois(i["ioc"])
                enrichment["whois"] = str(w.domain_name)
                risk += 5
            elif "ip" in i["type"].lower():
                obj = IPWhois(i["ioc"])
                rdap = obj.lookup_rdap(depth=1)
                enrichment["asn"] = rdap.get("asn")
                enrichment["country"] = rdap.get("asn_country_code")
                risk += 10
        except Exception:
            pass

        i["risk_score"] = risk
        i["enrichment"] = enrichment
        enriched.append(i)
    return enriched

# ---------------------- REPORT ----------------------
def generate_report(db_path, report_file):
    conn = pd.read_sql_query("SELECT * FROM intel", f"sqlite:///{db_path}")
    conn.to_csv(report_file, index=False)
    print(f"[+] Report saved as {report_file}")

# ---------------------- MAIN ----------------------
def main():
    raw = fetch_threat_data()
    if not raw:
        print("[!] No data fetched.")
        return

    normalized = normalize_data(raw)
    enriched = enrich_data(normalized)
    init_db(DB_PATH)
    store_records(DB_PATH, enriched)
    generate_report(DB_PATH, REPORT_FILE)
    print("[✓] Threat intelligence aggregation complete.")

if __name__ == "__main__":
    main()
