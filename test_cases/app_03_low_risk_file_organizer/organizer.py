"""
Application 3: Desktop File Organizer & Directory Cleaner (LOW RISK / MINOR VULNERABILITY)
Security Profile: Mostly benign utility, but demonstrates mild security warnings:
- Operates on user filesystem paths without strict sandboxed chroot.
- Uses unpinned generic libraries.
Expected Risk: Low to Mild (15% - 25%).
Verdict: APPROVED (LOW RISK - ~23.5% Risk Score).

[VIVA EXPLANATION - WHY THIS IS APPROVED / LOW RISK]:
1. Verdict: APPROVED (Score < 30% Threshold).
2. Why not 0% Risk?
   - File manipulation on the host filesystem: It scans and classifies files (`iterdir()`).
   - If an attacker passes an unrestricted relative path like `../../`, path traversal is theoretically possible without `resolve().is_relative_to()`.
3. Why Still Safe / Approved?
   - Zero malicious payload, zero backdoor, zero network communication.
   - Standard benign Python library usage (`shutil`, `pathlib`).
   - Pure dry-run simulation mode by default (no actual deletion or overwrite).
"""

# [SECURITY LINE EXPLANATION: SAFE STANDARD UTILITIES]
# Standard filesystem APIs used; no shell execution wrappers like os.system.
import os
import shutil
import sys
from pathlib import Path

# [SECURITY LINE EXPLANATION: STATIC SAFE EXTENSION WHITELIST]
# Whitelisted extensions ensure the script categorizes known file types predictably.
CATEGORY_MAPPING = {
    "Documents": [".pdf", ".docx", ".txt", ".xlsx", ".pptx"],
    "Images": [".png", ".jpg", ".jpeg", ".gif", ".svg"],
    "Code": [".py", ".js", ".html", ".css", ".json", ".sql"],
    "Archives": [".zip", ".tar", ".gz", ".7z", ".rar"]
}

class FileOrganizer:
    def __init__(self, target_directory: str):
        # [SECURITY AUDIT POINT: MILD PATH HANDLING RISK]
        # Path() wraps the input directory, but does not enforce chroot containment.
        # This contributes ~2-3% to the ambient risk score because host directories are read.
        self.target_dir = Path(target_directory)

    def scan_directory(self):
        """Scans folder and categorizes files based on extension."""
        categorized = {k: [] for k in CATEGORY_MAPPING}
        categorized["Others"] = []

        # [SECURITY LINE EXPLANATION: SAFE EXISTENCE CHECK]
        # Verifies directory existence before traversing, preventing runtime crashes.
        if not self.target_dir.exists():
            return categorized

        # [SECURITY LINE EXPLANATION: NON-RECURSIVE SAFE ENUMERATION]
        # .iterdir() only scans the immediate directory, preventing recursive directory exhaustion.
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
        """Simulates file relocation safely without executing disk write operations."""
        # [SECURITY LINE EXPLANATION: SAFE SIMULATION PATTERN]
        # Performs non-destructive inspection. No file deletion or unauthorized relocation.
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
