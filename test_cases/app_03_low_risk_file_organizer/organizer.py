"""
Application 3: Desktop File Organizer & Directory Cleaner (LOW RISK / MINOR VULNERABILITY)
Security Profile: Mostly benign utility, but demonstrates mild security warnings:
- Operates on user filesystem paths without strict sandboxed chroot.
- Uses unpinned generic libraries.
Expected Risk: Low to Mild (15% - 25%).
Verdict: APPROVED (LOW RISK).
"""

import os
import shutil
import sys
from pathlib import Path

CATEGORY_MAPPING = {
    "Documents": [".pdf", ".docx", ".txt", ".xlsx", ".pptx"],
    "Images": [".png", ".jpg", ".jpeg", ".gif", ".svg"],
    "Code": [".py", ".js", ".html", ".css", ".json", ".sql"],
    "Archives": [".zip", ".tar", ".gz", ".7z", ".rar"]
}

class FileOrganizer:
    def __init__(self, target_directory: str):
        self.target_dir = Path(target_directory)

    def scan_directory(self):
        """Scans folder and categorizes files based on extension."""
        categorized = {k: [] for k in CATEGORY_MAPPING}
        categorized["Others"] = []

        if not self.target_dir.exists():
            return categorized

        for file_path in self.target_dir.iterdir():
            if file_path.is_file():
                ext = file_path.suffix.lower()
                matched = False
                for cat, extensions in CATEGORY_MAPPING.items():
                    if ext in extensions:
                        categorized[cat].append(file_path.name)
                        matched = True
                        break
                if not matched:
                    categorized["Others"].append(file_path.name)
        return categorized

    def organize_dry_run(self):
        """Simulates file relocation safely."""
        scan = self.scan_directory()
        total_files = sum(len(v) for v in scan.values())
        print(f"Total files discovered: {total_files}")
        for cat, files in scan.items():
            if files:
                print(f" -> [{cat}]: {len(files)} files ({', '.join(files[:3])}...)")
        return total_files

def main():
    print("=== Automated File Organizer Utility ===")
    organizer = FileOrganizer(".")
    organizer.organize_dry_run()

if __name__ == "__main__":
    main()
