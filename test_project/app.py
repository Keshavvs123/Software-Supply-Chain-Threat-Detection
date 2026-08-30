# import os
# import subprocess
# import pickle
# import hashlib
# import sqlite3
# import yaml
# import random
# import tempfile


# # 1. Command Injection using os.system
# def command_injection():
#     user_input = input("Enter command: ")
#     os.system(user_input)  # Vulnerable


# # 2. Hardcoded password
# def hardcoded_password():
#     password = "admin123"
#     print("Password:", password)


# # 3. Weak cryptographic hashing
# def weak_hash():
#     data = "secret_data"
#     hash_value = hashlib.md5(data.encode()).hexdigest()  # MD5 is insecure
#     print("Hash:", hash_value)


# # 4. Shell Injection using subprocess
# def subprocess_injection():
#     command = input("Enter subprocess command: ")
#     subprocess.call(command, shell=True)  # Vulnerable


# # 5. Unsafe deserialization using pickle
# def unsafe_deserialization():
#     data = input("Enter serialized data: ")
#     pickle.loads(data.encode())  # Vulnerable


# # 6. SQL Injection vulnerability
# def sql_injection():
#     username = input("Enter username: ")
#     conn = sqlite3.connect("users.db")
#     cursor = conn.cursor()

#     query = "SELECT * FROM users WHERE username = '" + username + "'"
#     cursor.execute(query)  # Vulnerable


# # 7. Unsafe YAML loading
# def unsafe_yaml():
#     data = input("Enter YAML data: ")
#     yaml.load(data, Loader=yaml.Loader)  # Vulnerable


# # 8. Insecure random number generation
# def weak_random():
#     token = random.random()
#     print("Generated token:", token)


# # 9. Insecure temporary file
# def insecure_temp_file():
#     temp_file = tempfile.mktemp()  # Vulnerable
#     print("Temporary file:", temp_file)


# # 10. Insecure file permissions
# def insecure_permissions():
#     with open("secret.txt", "w") as f:
#         f.write("Sensitive Data")

#     os.chmod("secret.txt", 0o777)  # World writable


# if __name__ == "__main__":
#     command_injection()
#     hardcoded_password()
#     weak_hash()
#     subprocess_injection()
#     unsafe_deserialization()
#     sql_injection()
#     unsafe_yaml()
#     weak_random()
#     insecure_temp_file()
#     insecure_permissions()