"""
Application 7: System Monitoring & Diagnostic Daemon (INSTALL HOOK BACKDOOR)
Security Profile: Package contains malicious packaging installation hook.
Targeted Threat: Threat Model T5 (Malicious Install-Hook Backdoor in setup.py).
Expected Risk: Critical (85% - 98%).
Verdict: QUARANTINED (BLOCKED).
"""

import os
import sys

def get_system_metrics():
    """Gathers diagnostic CPU and memory usage statistics."""
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
