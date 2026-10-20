"""
Application 4: Weather & Currency Info Fetcher (MODERATE RISK / WARNING)
Security Profile: Useful CLI utility, but contains moderate security warnings:
- Outbound network requests without strict timeouts or certificate pinning.
- Loose dependency constraints with moderate blast radius.
- Mild SAST flag on unverified SSL / requests without explicit timeout.
Expected Risk: Moderate (35% - 48%).
Verdict: MONITOR (MEDIUM RISK).
"""

import sys
import json

def fetch_weather_mock(city_name: str) -> dict:
    """Simulates weather API query with formatted dictionary response."""
    # In practice: requests.get(f"https://api.weather.mock/{city_name}", verify=False)
    # verify=False triggers Bandit B501 warning (Unverified HTTPS request)
    sample_data = {
        "city": city_name,
        "temperature_c": 24.5,
        "condition": "Partly Cloudy",
        "humidity_percent": 65,
        "wind_speed_kmh": 14.2
    }
    return sample_data

def format_ascii_report(data: dict):
    print("=" * 40)
    print(f"WEATHER INTELLIGENCE REPORT: {data['city'].upper()}")
    print("=" * 40)
    print(f" Condition:   {data['condition']}")
    print(f" Temperature: {data['temperature_c']} C")
    print(f" Humidity:    {data['humidity_percent']}%")
    print(f" Wind:        {data['wind_speed_kmh']} km/h")
    print("=" * 40)

def main():
    target_city = "Bengaluru" if len(sys.argv) < 2 else sys.argv[1]
    res = fetch_weather_mock(target_city)
    format_ascii_report(res)

if __name__ == "__main__":
    main()
