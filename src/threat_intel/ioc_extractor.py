import re
from urllib.parse import urlparse


IP_PATTERN = re.compile(
    r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
)

DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-zA-Z0-9-]+\.)+"
    r"[a-zA-Z]{2,}\b"
)

HASH_PATTERN = re.compile(
    r"\b[a-fA-F0-9]{32}\b"
    r"|\b[a-fA-F0-9]{40}\b"
    r"|\b[a-fA-F0-9]{64}\b"
)


def extract_ips(text: str) -> list[str]:
    """Extract IPv4 addresses from text."""
    return IP_PATTERN.findall(text)


def extract_domains(text: str) -> list[str]:
    """Extract domain names from text."""
    domains = DOMAIN_PATTERN.findall(text)

    return [
        domain
        for domain in domains
        if not domain.replace(".", "").isdigit()
    ]


def extract_urls(text: str) -> list[str]:
    """Extract HTTP/HTTPS URLs from text."""
    url_pattern = re.compile(
        r"https?://[^\s]+"
    )

    return url_pattern.findall(text)


def extract_hashes(text: str) -> list[str]:
    """Extract MD5, SHA1, and SHA256 hashes."""
    return HASH_PATTERN.findall(text)


def extract_iocs(text: str) -> dict:
    """Extract common indicators of compromise."""
    return {
        "ips": sorted(set(extract_ips(text))),
        "domains": sorted(set(extract_domains(text))),
        "urls": sorted(set(extract_urls(text))),
        "hashes": sorted(set(extract_hashes(text))),
    }