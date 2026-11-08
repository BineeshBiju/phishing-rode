"""
CyberScape Geo-IP Resolver & Network Telemetry
Resolves domain to IP via socket and queries geo-location coordinates and ISP metadata.
"""

import socket
from urllib.parse import urlparse
import requests


def country_code_to_flag(code: str) -> str:
    """Convert 2-letter ISO country code into Unicode Flag Emoji."""
    if not code or len(code) != 2:
        return "🌐"
    code = code.upper()
    try:
        return chr(ord(code[0]) + 127397) + chr(ord(code[1]) + 127397)
    except Exception:
        return "🌐"


def resolve_geo_ip(target: str) -> dict:
    """
    Given a URL or domain, resolve the host IP and query network telemetry:
    ISP, Organization, ASN, Country, City, Region, Latitude, Longitude.
    """
    if "://" in target:
        hostname = urlparse(target).hostname or target
    else:
        hostname = target.split("/")[0]

    hostname = (hostname or "").split(":")[0].strip()

    if not hostname:
        return {
            "status": "error",
            "ip": "Unknown",
            "hostname": "Unknown",
            "country": "Unknown",
            "country_code": "UN",
            "flag": "🌐",
            "city": "Unknown",
            "region": "Unknown",
            "isp": "Unknown ISP",
            "org": "Unknown Organization",
            "asn": "N/A",
            "latitude": 0.0,
            "longitude": 0.0,
            "coordinates": "0.0000, 0.0000"
        }

    # Resolve IP using standard library socket
    resolved_ip = None
    try:
        resolved_ip = socket.gethostbyname(hostname)
    except socket.gaierror:
        pass

    if not resolved_ip:
        # Fallback to hostname if it's already an IP
        if hostname.replace(".", "").isdigit():
            resolved_ip = hostname
        else:
            return {
                "status": "unresolved",
                "ip": "Unresolved Host",
                "hostname": hostname,
                "country": "Undetermined",
                "country_code": "XX",
                "flag": "🌐",
                "city": "Unknown",
                "region": "Unknown",
                "isp": "DNS Unresolved",
                "org": "DNS Unresolved",
                "asn": "N/A",
                "latitude": 0.0,
                "longitude": 0.0,
                "coordinates": "0.0000, 0.0000"
            }

    # Query IP-API for geolocation data
    try:
        url = f"http://ip-api.com/json/{resolved_ip}?fields=status,message,country,countryCode,region,regionName,city,lat,lon,timezone,isp,org,as,query"
        resp = requests.get(url, timeout=3.5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get("status") == "success":
                lat = data.get("lat", 0.0)
                lon = data.get("lon", 0.0)
                country = data.get("country", "Unknown")
                country_code = data.get("countryCode", "UN")
                return {
                    "status": "success",
                    "ip": resolved_ip,
                    "hostname": hostname,
                    "country": country,
                    "country_code": country_code,
                    "flag": country_code_to_flag(country_code),
                    "city": data.get("city", "Unknown City"),
                    "region": data.get("regionName", "Unknown Region"),
                    "isp": data.get("isp", "Private / Autonomous Network"),
                    "org": data.get("org") or data.get("isp") or "Unknown Registrar",
                    "asn": data.get("as", "N/A"),
                    "latitude": lat,
                    "longitude": lon,
                    "coordinates": f"{lat:.4f}, {lon:.4f}"
                }
    except Exception:
        pass

    # Fallback if external API is unreachable or rate limited
    return {
        "status": "partial",
        "ip": resolved_ip,
        "hostname": hostname,
        "country": "Global Network",
        "country_code": "US",
        "flag": "🌐",
        "city": "Autonomous System",
        "region": "Global",
        "isp": "Cloud Network Provider",
        "org": "Enterprise Host Network",
        "asn": "AS-HOST",
        "latitude": 37.751,
        "longitude": -122.42,
        "coordinates": "37.7510, -122.4200"
    }
