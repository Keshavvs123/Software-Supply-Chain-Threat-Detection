import os
import sqlite3
import json
import re
import pandas as pd

DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "outputs", "cve_database.sqlite"))

def get_db_connection():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_cve_database():
    """
    Initializes SQLite tables for local CVE caching and offline vulnerability lookups.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS cve_records (
        cve_id TEXT PRIMARY KEY,
        cvss_score REAL,
        exploitability REAL,
        published_date TEXT,
        severity TEXT,
        description TEXT,
        cwe_list TEXT
    )
    """)
    
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS package_vuln_cache (
        package_key TEXT,
        version TEXT,
        vulns_json TEXT,
        cached_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        PRIMARY KEY (package_key, version)
    )
    """)
    
    conn.commit()
    conn.close()
    
    # Pre-seed from Excel dataset if database is empty
    seed_from_dataset()

def seed_from_dataset():
    """
    Seeds SQLite database from Supply_Chain_Risk_Dataset_v2.xlsx if available.
    """
    conn = get_db_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT COUNT(*) FROM cve_records")
    count = cursor.fetchone()[0]
    if count > 100:
        conn.close()
        return

    excel_candidates = [
        os.path.join("dataset", "Supply_Chain_Risk_Dataset_v2.xlsx"),
        os.path.join("test_project", "Supply_Chain_Risk_Dataset_v2.xlsx"),
        "Supply_Chain_Risk_Dataset_v2.xlsx"
    ]
    
    excel_path = None
    for p in excel_candidates:
        if os.path.exists(p):
            excel_path = p
            break
            
    if excel_path:
        try:
            df_vuln = pd.read_excel(excel_path, sheet_name="Vulnerabilities")
            records = []
            for _, row in df_vuln.iterrows():
                cve_id = str(row.get("CVE_ID", "")).strip().upper()
                if cve_id and cve_id != "NAN":
                    cvss = float(row.get("CVSS_Score", 5.0)) if pd.notna(row.get("CVSS_Score")) else 5.0
                    exp = float(row.get("Exploitability_Score", 0.5)) if pd.notna(row.get("Exploitability_Score")) else 0.5
                    pub = str(row.get("Published", "2024-01-01")).split("T")[0]
                    sev = str(row.get("Severity", "MEDIUM"))
                    desc = str(row.get("Description", ""))
                    
                    cwes = json.dumps(re.findall(r"CWE-\d+", desc) or ["CWE-Unknown"])
                    records.append((cve_id, cvss, exp, pub, sev, desc, cwes))
                    
            cursor.executemany("""
            INSERT OR REPLACE INTO cve_records (cve_id, cvss_score, exploitability, published_date, severity, description, cwe_list)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, records)
            conn.commit()
            print(f"[CVE-DB] Seeded {len(records)} vulnerability records from {excel_path} into local SQLite database.")
        except Exception as e:
            print(f"[CVE-DB] Note on dataset seeding: {e}")
            
    conn.close()

def get_cached_package_vulns(package_name, version):
    """
    Fast indexed lookup from local SQLite cache. Returns list of parsed vulns or None.
    """
    init_cve_database()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute(
        "SELECT vulns_json FROM package_vuln_cache WHERE package_key = ? AND version = ?",
        (package_name.strip().lower(), str(version).strip())
    )
    row = cursor.fetchone()
    conn.close()
    if row and row["vulns_json"]:
        try:
            return json.loads(row["vulns_json"])
        except Exception:
            return None
    return None

def store_cached_package_vulns(package_name, version, vulns_list):
    """
    Saves parsed vulnerabilities into SQLite cache for offline zero-latency reuse.
    """
    init_cve_database()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
    INSERT OR REPLACE INTO package_vuln_cache (package_key, version, vulns_json)
    VALUES (?, ?, ?)
    """, (package_name.strip().lower(), str(version).strip(), json.dumps(vulns_list)))
    conn.commit()
    conn.close()

def get_cve_record(cve_id):
    """
    Retrieves detailed CVE metadata from local SQLite database.
    """
    init_cve_database()
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM cve_records WHERE cve_id = ?", (cve_id.strip().upper(),))
    row = cursor.fetchone()
    conn.close()
    if row:
        return {
            "cve_id": row["cve_id"],
            "cvss_score": row["cvss_score"],
            "exploitability": row["exploitability"],
            "published_date": row["published_date"],
            "severity": row["severity"],
            "description": row["description"],
            "cwes": json.loads(row["cwe_list"]) if row["cwe_list"] else ["CWE-Unknown"]
        }
    return None
