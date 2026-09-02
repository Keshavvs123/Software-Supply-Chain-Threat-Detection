import os
import sqlite3
import urllib.request
import json
import re
from datetime import datetime
import ssl

# Bypass SSL validation issues if any local cert configs are outdated
ssl_context = ssl._create_unverified_context()

DB_PATH = os.path.join("outputs", "cyber_intel_db.sqlite")

def init_database():
    """
    Initializes the SQLite Database schema.
    """
    os.makedirs("outputs", exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Packages table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS packages (
        name TEXT PRIMARY KEY,
        version TEXT,
        age_days REAL,
        release_frequency REAL,
        release_burstiness REAL,
        last_update_days REAL,
        stars INTEGER,
        forks INTEGER,
        open_issues INTEGER,
        maintainer_count INTEGER,
        maintainer_churn REAL,
        commit_activity REAL,
        openssf_score REAL,
        downloads INTEGER,
        last_scanned TEXT
    )
    """)
    
    # Vulnerabilities table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS vulnerabilities (
        id TEXT PRIMARY KEY,
        package_name TEXT,
        cvss_score REAL,
        cwe TEXT,
        published_date TEXT,
        exploitability REAL,
        details TEXT,
        FOREIGN KEY (package_name) REFERENCES packages (name)
    )
    """)
    
    # Historical risk scores table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS package_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        package_name TEXT,
        version TEXT,
        risk_score REAL,
        confidence_score REAL,
        timestamp TEXT,
        FOREIGN KEY (package_name) REFERENCES packages (name)
    )
    """)
    
    conn.commit()
    conn.close()

def parse_github_url(project_urls):
    """
    Extracts owner and repo name from PyPI project urls.
    """
    if not project_urls:
        return None
    
    github_pattern = re.compile(r"github\.com/([^/]+)/([^/]+)")
    for name, url in project_urls.items():
        if url and "github.com" in url:
            match = github_pattern.search(url)
            if match:
                owner, repo = match.group(1), match.group(2)
                # Clean trailing slashes or sub-routes
                repo = repo.split(".git")[0].split("/")[0]
                return f"{owner}/{repo}"
    return None

def fetch_github_metadata(repo_path):
    """
    Queries GitHub API for repository stars, forks, issues.
    """
    token = os.environ.get("GITHUB_TOKEN")
    url = f"https://api.github.com/repos/{repo_path}"
    headers = {"User-Agent": "SupplyChainThreatDetector"}
    if token:
        headers["Authorization"] = f"token {token}"
        
    try:
        req = urllib.request.Request(url, headers=headers)
        with urllib.request.urlopen(req, timeout=3, context=ssl_context) as response:
            data = json.loads(response.read().decode())
            return {
                "stars": data.get("stargazers_count", 0),
                "forks": data.get("forks_count", 0),
                "open_issues": data.get("open_issues_count", 0),
                "commit_activity": 1.5, # default activity rate
                "maintainer_churn": 0.1
            }
    except Exception as e:
        # Fallback due to rate limits or invalid repos
        return {
            "stars": 150, 
            "forks": 30, 
            "open_issues": 5,
            "commit_activity": 1.0,
            "maintainer_churn": 0.2
        }

def fetch_openssf_scorecard(repo_path):
    """
    Queries OpenSSF Scorecard API.
    """
    url = f"https://api.securityscorecards.dev/projects/github.com/{repo_path}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SupplyChainThreatDetector"})
        with urllib.request.urlopen(req, timeout=3, context=ssl_context) as response:
            data = json.loads(response.read().decode())
            return data.get("score", 6.0)
    except Exception:
        # Default average scorecard score
        return 5.5

def fetch_pypi_metadata(package_name):
    """
    Fetches real metadata from PyPI JSON API and computes temporal metrics.
    """
    url = f"https://pypi.org/pypi/{package_name}/json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SupplyChainThreatDetector"})
        with urllib.request.urlopen(req, timeout=4, context=ssl_context) as response:
            data = json.loads(response.read().decode())
            info = data.get("info", {})
            releases = data.get("releases", {})
            
            # Compute temporal metrics from release dates
            release_dates = []
            for ver, files in releases.items():
                if files:
                    # Parse upload time of first file in release list
                    upload_time = files[0].get("upload_time_iso_8601") or files[0].get("upload_time")
                    if upload_time:
                        try:
                            # Format: 2023-10-12T14:30:00Z or similar
                            dt = datetime.fromisoformat(upload_time.replace("Z", "+00:00"))
                            release_dates.append(dt)
                        except ValueError:
                            pass
            
            # Default fallback values
            age_days = 365.0
            release_frequency = 12.0 # releases per year
            release_burstiness = 0.5
            last_update_days = 30.0
            
            if release_dates:
                release_dates.sort()
                now = datetime.now(release_dates[0].tzinfo)
                
                # Age
                first_release = release_dates[0]
                latest_release = release_dates[-1]
                age_days = max((now - first_release).days, 1.0)
                last_update_days = max((now - latest_release).days, 0.1)
                
                # Frequency (releases per month)
                release_frequency = len(release_dates) / max((age_days / 30.4), 0.1)
                
            # Release burstiness and real chronological intervals
            intervals = []
            if len(release_dates) > 1:
                for i in range(1, len(release_dates)):
                    intervals.append(float((release_dates[i] - release_dates[i-1]).days))
                mean_interval = sum(intervals) / len(intervals)
                variance = sum((x - mean_interval)**2 for x in intervals) / len(intervals)
                sd_interval = variance**0.5
                release_burstiness = sd_interval / max(mean_interval, 1.0)
            else:
                mean_interval = 30.0
                release_burstiness = 0.2
            
            # Extract maintainers / authors
            maintainer = info.get("maintainer") or info.get("author") or ""
            maintainer_count = len(maintainer.split(",")) if maintainer else 1
            
            # Parse github path
            github_path = parse_github_url(info.get("project_urls"))
            
            # Downloads proxy from PyPI downloads (not available directly on API, use defaults/stars ratio)
            downloads = int(info.get("downloads", {}).get("last_month", 500000))
            if downloads <= 0:
                downloads = 500000
                
            return {
                "version": info.get("version", "Unknown"),
                "age_days": age_days,
                "release_frequency": release_frequency,
                "release_burstiness": release_burstiness,
                "last_update_days": last_update_days,
                "release_intervals": intervals[-5:] if intervals else [30.0],
                "avg_release_interval_days": mean_interval,
                "maintainer_count": maintainer_count,
                "github_path": github_path,
                "downloads": downloads,
                "author": info.get("author", "Unknown")
            }
    except Exception as e:
        print(f"Error fetching PyPI metadata for {package_name}: {e}")
        return None

def verify_and_enrich_package(package_name, version=None):
    """
    Implements Known Package Verification and Dataset Enrichment.
    """
    init_database()
    package_name = package_name.lower()
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # 1. Check if package exists in DB
    cursor.execute("SELECT * FROM packages WHERE name = ?", (package_name,))
    pkg_row = cursor.fetchone()
    
    historical_vulns = []
    
    if pkg_row:
        # Known package: retrieve historical vulnerabilities
        print(f"Known package detected in database: {package_name}")
        cursor.execute("SELECT id, cvss_score, cwe, published_date, exploitability, details FROM vulnerabilities WHERE package_name = ?", (package_name,))
        rows = cursor.fetchall()
        for r in rows:
            historical_vulns.append({
                "cve_id": r[0],
                "cvss_score": r[1],
                "cwes": [c.strip() for c in r[2].split(",") if c],
                "published": r[3],
                "exploitability": r[4],
                "details": r[5]
            })
            
        # Keep track of history and return
        p_dict = {
            "name": pkg_row[0],
            "version": pkg_row[1],
            "age_days": pkg_row[2],
            "release_frequency": pkg_row[3],
            "release_burstiness": pkg_row[4],
            "last_update_days": pkg_row[5],
            "stars": pkg_row[6],
            "forks": pkg_row[7],
            "open_issues": pkg_row[8],
            "maintainer_count": pkg_row[9],
            "maintainer_churn": pkg_row[10],
            "commit_activity": pkg_row[11],
            "openssf_score": pkg_row[12],
            "downloads": pkg_row[13],
            "historical_vulnerabilities": historical_vulns
        }
        conn.close()
        return p_dict

    # 2. Package not in DB: Fetch metadata and enrich dataset
    print(f"New package detected, running metadata collection for: {package_name}")
    pypi_data = fetch_pypi_metadata(package_name)
    
    if not pypi_data:
        # Fallback profile
        pypi_data = {
            "version": version or "Unknown",
            "age_days": 365.0,
            "release_frequency": 5.0,
            "release_burstiness": 0.4,
            "last_update_days": 45.0,
            "maintainer_count": 1,
            "github_path": None,
            "downloads": 10000,
            "author": "Unknown"
        }
        
    github_path = pypi_data["github_path"]
    github_data = {"stars": 100, "forks": 20, "open_issues": 2, "commit_activity": 1.0, "maintainer_churn": 0.1}
    openssf_score = 5.0
    
    if github_path:
        github_data = fetch_github_metadata(github_path)
        openssf_score = fetch_openssf_scorecard(github_path)
        
    last_scanned = datetime.now().isoformat()
    
    # Store package profile
    cursor.execute("""
    INSERT OR REPLACE INTO packages (
        name, version, age_days, release_frequency, release_burstiness, last_update_days,
        stars, forks, open_issues, maintainer_count, maintainer_churn, commit_activity,
        openssf_score, downloads, last_scanned
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (
        package_name, pypi_data["version"], pypi_data["age_days"], pypi_data["release_frequency"],
        pypi_data["release_burstiness"], pypi_data["last_update_days"], github_data["stars"],
        github_data["forks"], github_data["open_issues"], pypi_data["maintainer_count"],
        github_data["maintainer_churn"], github_data["commit_activity"], openssf_score,
        pypi_data["downloads"], last_scanned
    ))
    
    conn.commit()
    conn.close()
    
    return {
        "name": package_name,
        "version": pypi_data["version"],
        "age_days": pypi_data["age_days"],
        "release_frequency": pypi_data["release_frequency"],
        "release_burstiness": pypi_data["release_burstiness"],
        "last_update_days": pypi_data["last_update_days"],
        "stars": github_data["stars"],
        "forks": github_data["forks"],
        "open_issues": github_data["open_issues"],
        "maintainer_count": pypi_data["maintainer_count"],
        "maintainer_churn": github_data["maintainer_churn"],
        "commit_activity": github_data["commit_activity"],
        "openssf_score": openssf_score,
        "downloads": pypi_data["downloads"],
        "historical_vulnerabilities": []
    }

def record_vulnerabilities(package_name, vulns):
    """
    Appends newly discovered vulnerabilities into the DB without duplication.
    """
    init_database()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    for v in vulns:
        cve_id = v.get("cve_id")
        cvss = v.get("cvss_score", 5.0)
        cwe_str = ",".join(v.get("cwes", ["CWE-Unknown"]))
        published = v.get("published", "")
        # Exploitability approximation (CVSS exploitability score fraction)
        exploitability = max(cvss - 3.0, 1.0) / 7.0
        details = v.get("details", v.get("summary", ""))
        
        cursor.execute("""
        INSERT OR REPLACE INTO vulnerabilities (
            id, package_name, cvss_score, cwe, published_date, exploitability, details
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (cve_id, package_name.lower(), cvss, cwe_str, published, exploitability, details))
        
    conn.commit()
    conn.close()

def log_risk_history(package_name, version, risk_score, confidence_score):
    """
    Logs prediction history for packages.
    """
    init_database()
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    timestamp = datetime.now().isoformat()
    cursor.execute("""
    INSERT INTO package_history (
        package_name, version, risk_score, confidence_score, timestamp
    ) VALUES (?, ?, ?, ?, ?)
    """, (package_name.lower(), version, risk_score, confidence_score, timestamp))
    
    conn.commit()
    conn.close()
