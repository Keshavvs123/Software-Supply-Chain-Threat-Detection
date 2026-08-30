import urllib.request
import json
import ssl
from concurrent.futures import ThreadPoolExecutor

ssl_context = ssl._create_unverified_context()

PACKAGES = [
    "boto3", "botocore", "awscli", "google-api-python-client", "django", 
    "numpy", "pandas", "matplotlib", "scipy", "scikit-learn", "cryptography", 
    "pyyaml", "jinja2", "flask", "werkzeug", "celery", "redis", "sqlalchemy", 
    "pillow", "click", "tqdm", "six", "pytz", "attrs", "importlib-metadata", 
    "urllib3", "requests", "pydantic", "fastapi", "black", "mypy", "flake8", 
    "pylint", "astroid", "isort", "tornado", "twisted", "paramiko", "salt", 
    "kubernetes", "azure-mgmt-compute", "azure-mgmt-storage", "azure-core", 
    "tensorflow", "torch", "scrapy", "pika", "ansible", "ansible-core",
    "azure-mgmt-network", "azure-mgmt-resource", "google-cloud-monitoring", 
    "google-cloud-logging", "google-cloud-bigquery-storage", "sphinx", 
    "docutils", "pip", "setuptools", "virtualenv", "tox", "coverage", 
    "protobuf", "grpcio", "psutil", "pymongo", "psycopg2", 
    "mysql-connector-python", "simplejson"
]

def check_package(name):
    url = f"https://pypi.org/pypi/{name}/json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SupplyChainThreatDetector"})
        with urllib.request.urlopen(req, timeout=5, context=ssl_context) as response:
            data = json.loads(response.read().decode())
            releases = data.get("releases", {})
            return name, len(releases)
    except Exception as e:
        return name, 0

if __name__ == "__main__":
    print(f"Checking version counts for {len(PACKAGES)} packages...")
    total = 0
    results = []
    with ThreadPoolExecutor(max_workers=10) as executor:
        for name, count in executor.map(check_package, PACKAGES):
            if count > 0:
                print(f"  {name}: {count} versions")
                results.append((name, count))
                total += count
            else:
                print(f"  {name}: Failed or 0")
    print(f"\nTotal versions: {total}")
