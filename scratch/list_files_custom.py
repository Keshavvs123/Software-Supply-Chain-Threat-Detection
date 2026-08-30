import os

project_dir = r"c:\Users\keshav\OneDrive\Documents\caps_pjct\project\project"
for root, dirs, files in os.walk(project_dir):
    # Exclude venv, __pycache__, .git
    dirs[:] = [d for d in dirs if d not in ('venv', '__pycache__', '.git', '.DS_Store', '__MACOSX')]
    for file in files:
        if file.endswith(('.py', '.html', '.txt', '.csv', '.sqlite', '.pt')):
            full_path = os.path.join(root, file)
            rel_path = os.path.relpath(full_path, project_dir)
            size = os.path.getsize(full_path)
            print(f"File: {rel_path} | Size: {size} bytes")
