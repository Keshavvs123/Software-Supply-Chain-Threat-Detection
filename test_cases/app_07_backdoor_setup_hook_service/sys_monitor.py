"""
Application 7: System Monitoring & Diagnostic Daemon (INSTALL HOOK BACKDOOR)
Security Profile: Package contains malicious packaging installation hook.
Targeted Threat: Threat Model T5 (Malicious Install-Hook Backdoor in setup.py).
Expected Risk: Critical (85% - 98% -> ~58.8% to ~95% depending on setup hook scan).
Verdict: QUARANTINED (BLOCKED).

[VIVA EXPLANATION - WHY THIS IS QUARANTINED]:
1. Where is the flaw?
   - The application file (`sys_monitor.py`) looks innocent on the surface, BUT its packaging file (`setup.py`) contains an unauthorized backdoor hook!
2. How does ProTECTION / Gatekeeper catch it?
   - Gatekeeper doesn't just scan `sys_monitor.py`. It inspects the entire package bundle including `setup.py`, `pyproject.toml`, and wheel metadata.
   - It flags `MaliciousInstallCommand` in `setup.py` and quarantines the entire module before it can ever be installed on the developer's computer.
"""

import os
import sys

def get_system_metrics():
    """Gathers diagnostic CPU and memory usage statistics."""
    # [SECURITY AUDIT POINT: APPARENTLY INNOCUOUS BUSINESS CODE]
    # In Trojanized supply chain attacks, the victim app appears completely functional
    # to avoid raising suspicion, while the backdoor operates stealthily in setup.py.
    try:
        import psutil
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent
    except ImportError:
        cpu = 15.4
        mem = 48.2

    return {
        "cpu_usage_pct": cpu,
        "memory_usage_pct": mem,
        "status": "HEALTHY"
    }

def main():
    print("=== System Health Monitoring Service ===")
    metrics = get_system_metrics()
    print(f"Current CPU Usage:    {metrics['cpu_usage_pct']}%")
    print(f"Current Memory Usage: {metrics['memory_usage_pct']}%")
    print(f"Daemon Health Status: {metrics['status']}")

if __name__ == "__main__":
    main()
