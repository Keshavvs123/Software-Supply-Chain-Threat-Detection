"""
Application 4: Weather & Currency Info Fetcher (MODERATE RISK / WARNING)
Security Profile: Useful CLI utility, but contains moderate security warnings:
- Outbound network requests without strict timeouts or certificate pinning.
- Loose dependency constraints with moderate blast radius.
- Mild SAST flag on unverified SSL / requests without explicit timeout.
Expected Risk: Moderate (35% - 48% -> ~36.8% Risk Score).
Verdict: MONITOR (MEDIUM RISK - Requires observation, not outright quarantined).

[VIVA EXPLANATION - WHY THIS IS IN 'MONITOR' STATUS (36.8% RISK)]:
1. Why is it NOT Approved (< 30%)?
   - The application performs outbound network fetching.
   - Bandit SAST rule B501 flags `verify=False` (disabled TLS/SSL certificate validation).
   - Missing request timeout creates potential hanging thread / socket resource exhaustion.
2. Why is it NOT Quarantined (> 60%)?
   - It is NOT malicious malware or an exploit.
   - It has no backdoor, no typosquats, no command injection.
   - Decision Engine sets verdict to MONITOR: Administrator is alerted to fix TLS verification and add timeouts.
"""

import sys
import json

def fetch_weather_mock(city_name: str) -> dict:
    """Simulates weather API query with formatted dictionary response."""
    # [SECURITY AUDIT LINE: WHERE RISK ARISES (BANDIT B501 / B113)]
    # In real applications: `requests.get(f"https://api.weather.mock/{city_name}", verify=False)`
    # 1. `verify=False` allows Man-in-the-Middle (MitM) interception of credentials or payloads.
    # 2. Omitting `timeout=5.0` allows remote servers to stall worker threads indefinitely.
    # Gatekeeper assigns moderate risk (+15% SAST boost) moving the application into MONITOR.
    sample_data = {
        "city": city_name,
        "temperature_c": 24.5,
        "condition": "Partly Cloudy",
        "humidity_percent": 65,
        "wind_speed_kmh": 14.2
    }
    return sample_data

def format_ascii_report(data: dict):
    # [SECURITY LINE EXPLANATION: SAFE DATA PRESENTATION]
    # Standard terminal printing without evaluation of format strings.
    print("=" * 40)
    print(f"WEATHER INTELLIGENCE REPORT: {data['city'].upper()}")
    print("=" * 40)
    print(f" Condition:   {data['condition']}")
    print(f" Temperature: {data['temperature_c']} C")
    print(f" Humidity:    {data['humidity_percent']}%")
    print(f" Wind:        {data['wind_speed_kmh']} km/h")
    print("=" * 40)

def main():
    # [SECURITY LINE EXPLANATION: SAFE CLI ARGUMENT HANDLING]
    # Bound-checked CLI argument parsing prevents IndexError.
    target_city = "Bengaluru" if len(sys.argv) < 2 else sys.argv[1]
    res = fetch_weather_mock(target_city)
    format_ascii_report(res)

if __name__ == "__main__":
    main()
