import os
import subprocess
import pickle
import hashlib
import sqlite3
import yaml
import random
import tempfile

# 1. Command Injection using os.system
def command_injection(user_input="whoami"):
    os.system(user_input)  # Vulnerable: B605 / B607

# 2. Hardcoded password
def hardcoded_password():
    password = "admin123"  # Vulnerable: B105
    print("Password:", password)

# 3. Weak cryptographic hashing
def weak_hash(data="secret_data"):
    hash_value = hashlib.md5(data.encode()).hexdigest()  # Vulnerable: B303 / B324
    print("Hash:", hash_value)

# 4. Shell Injection using subprocess
def subprocess_injection(command="echo alert"):
    subprocess.call(command, shell=True)  # Vulnerable: B602

# 5. Unsafe deserialization using pickle
def unsafe_deserialization(data=None):
    if data is None:
        data = pickle.dumps({"user": "admin"})
    pickle.loads(data)  # Vulnerable: B301

# 6. SQL Injection vulnerability
def sql_injection(username="admin' OR '1'='1"):
    conn = sqlite3.connect(":memory:")
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE users (username TEXT)")
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor.execute(query)  # Vulnerable: B608

# 7. Unsafe YAML loading
def unsafe_yaml(data="test: 123"):
    yaml.load(data, Loader=yaml.Loader)  # Vulnerable: B506

# 8. Insecure random number generation
def weak_random():
    token = random.random()  # Vulnerable: B311
    print("Generated token:", token)

# 9. Insecure temporary file
def insecure_temp_file():
    temp_file = tempfile.mktemp()  # Vulnerable: B306
    print("Temporary file:", temp_file)

# 10. Insecure file permissions
def insecure_permissions():
    secret_path = "secret_test.txt"
    with open(secret_path, "w") as f:
        f.write("Sensitive Data")
    os.chmod(secret_path, 0o777)  # Vulnerable: B103
    if os.path.exists(secret_path):
        os.remove(secret_path)

if __name__ == "__main__":
    try:
        command_injection()
        hardcoded_password()
        weak_hash()
        subprocess_injection()
        unsafe_deserialization()
        sql_injection()
        unsafe_yaml()
        weak_random()
        insecure_temp_file()
        insecure_permissions()
    except Exception as e:
        print(f"Executed test project vulnerabilities demonstration: {e}")