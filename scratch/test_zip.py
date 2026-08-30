import urllib.request
import ssl
import zipfile
import io

ssl_context = ssl._create_unverified_context()

def test_download_gcs_zip():
    url = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"
    print("Downloading OSV PyPI GCS database ZIP...")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SupplyChainThreatDetector"})
        with urllib.request.urlopen(req, timeout=15, context=ssl_context) as response:
            data = response.read()
            print(f"Downloaded {len(data)} bytes.")
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                namelist = z.namelist()
                print(f"Total files in ZIP: {len(namelist)}")
    except Exception as e:
        print("Failed:", e)

if __name__ == "__main__":
    test_download_gcs_zip()
