import ipaddress


def classify_ip(ip: str) -> str:
    """Classify an IP address as private, public, or invalid."""
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return "INVALID"

    if address.is_private:
        return "PRIVATE"

    return "PUBLIC"


def enrich_ip(ip: str) -> dict:
    """Return basic threat-intelligence context for an IP."""
    classification = classify_ip(ip)

    if classification == "INVALID":
        return {
            "indicator": ip,
            "type": "IP",
            "classification": "INVALID",
            "threat_score": 0,
            "reputation": "UNKNOWN",
            "source": "LOCAL",
        }

    if classification == "PRIVATE":
        return {
            "indicator": ip,
            "type": "IP",
            "classification": "PRIVATE",
            "threat_score": 0,
            "reputation": "INTERNAL",
            "source": "LOCAL",
        }

    return {
        "indicator": ip,
        "type": "IP",
        "classification": "PUBLIC",
        "threat_score": 0,
        "reputation": "UNKNOWN",
        "source": "LOCAL",
    }


def enrich_iocs(iocs: dict) -> dict:
    """Enrich extracted IOCs with threat-intelligence context."""
    enriched = {
        "ips": [],
        "domains": [],
        "urls": [],
        "hashes": [],
    }

    for ip in iocs.get("ips", []):
        enriched["ips"].append(
            enrich_ip(ip)
        )

    for domain in iocs.get("domains", []):
        enriched["domains"].append({
            "indicator": domain,
            "type": "DOMAIN",
            "threat_score": 0,
            "reputation": "UNKNOWN",
            "source": "LOCAL",
        })

    for url in iocs.get("urls", []):
        enriched["urls"].append({
            "indicator": url,
            "type": "URL",
            "threat_score": 0,
            "reputation": "UNKNOWN",
            "source": "LOCAL",
        })

    for file_hash in iocs.get("hashes", []):
        enriched["hashes"].append({
            "indicator": file_hash,
            "type": "HASH",
            "threat_score": 0,
            "reputation": "UNKNOWN",
            "source": "LOCAL",
        })

    return enriched