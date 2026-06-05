import re
import math
import subprocess
import dns.resolver
import ssl
import socket
from urllib.parse import urlparse
from Levenshtein import distance as levenshtein

from meshwall.models import BlockedDomain
from meshwall.db import SessionLocal

# Common popular domains for typosquat detection
POPULAR_DOMAINS = [
    'google.com', 'facebook.com', 'apple.com', 'microsoft.com', 'amazon.com',
    'netflix.com', 'paypal.com', 'twitter.com', 'instagram.com', 'github.com',
    'discord.com', 'dropbox.com', 'adobe.com', 'office.com', 'linkedin.com',
    'whatsapp.com', 'youtube.com', 'reddit.com', 'wikipedia.org', 'tiktok.com'
]

# Keywords commonly found in tracking/telemetry domains
TRACKER_KEYWORDS = [
    'analytics', 'track', 'pixel', 'telemetry', 'beacon', 'metrics',
    'collect', 'stats', 'log', 'event', 'ads', 'adservice', 'doubleclick',
    'facebook', 'google', 'amazon-adsystem', 'scorecardresearch',
    'crashlytics', 'appsflyer', 'adjust', 'branch', 'mixpanel', 'amplitude'
]

def _entropy(string):
    """Calculate Shannon entropy of a string."""
    if not string:
        return 0
    prob = [float(string.count(c)) / len(string) for c in set(string)]
    return -sum(p * math.log(p) / math.log(2.0) for p in prob)

def _is_suspicious(domain):
    """Check for tracking/telemetry keywords and high entropy subdomains."""
    domain_lower = domain.lower()
    # Check for known tracker keywords
    for keyword in TRACKER_KEYWORDS:
        if keyword in domain_lower:
            return True, f"Contains tracker keyword '{keyword}'"
    # Check subdomain entropy (likely random if high)
    parts = domain.split('.')
    if len(parts) > 2:
        sub = '.'.join(parts[:-2])  # e.g., "some-long-random" from sub.example.com
        if len(sub) > 10 and _entropy(sub) > 3.5:  # high entropy
            return True, "High entropy subdomain (likely tracking/DGA)"
    return False, None

def check_domain(domain):
    """Perform comprehensive passive checks: blocklist, patterns, DNS, TLS, CNAME."""
    result = {'domain': domain, 'passed': True, 'issues': []}

    # 1. Blocklist lookup (exact match)
    db = SessionLocal()
    try:
        if db.query(BlockedDomain).filter(BlockedDomain.domain == domain).first():
            result['passed'] = False
            result['issues'].append('Domain is already in MeshWall blocklist')
            return result
    finally:
        db.close()

    # 2. Parent domain check
    parts = domain.split('.')
    db = SessionLocal()
    try:
        for i in range(1, len(parts)-1):
            parent = '.'.join(parts[i:])
            if db.query(BlockedDomain).filter(BlockedDomain.domain == parent).first():
                result['passed'] = False
                result['issues'].append(f'Parent domain {parent} is blocked')
                return result
    finally:
        db.close()

    # 3. Pattern detection (keywords, entropy)
    suspicious, reason = _is_suspicious(domain)
    if suspicious:
        result['passed'] = False
        result['issues'].append(reason)

    # 4. Typosquat detection (only if still passing, to not override earlier fails)
    if result['passed']:
        is_typo, similar = detect_typosquat(domain)
        if is_typo:
            result['passed'] = False
            result['issues'].append(f'Possible typosquat of {similar}')

    # 5. Passive DNS/TLS/CNAME checks (only if still passing, to not waste time)
    if result['passed']:
        # DNS A record check
        try:
            answers = dns.resolver.resolve(domain, 'A')
            if not answers:
                result['passed'] = False
                result['issues'].append('No DNS A record found')
        except Exception as e:
            result['passed'] = False
            result['issues'].append(f'DNS A record error: {str(e)}')

    if result['passed']:
        # TLS certificate check
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                s.settimeout(5)
                s.connect((domain, 443))
                cert = s.getpeercert()
                if not cert:
                    result['passed'] = False
                    result['issues'].append('No TLS certificate presented')
        except ssl.SSLError as e:
            result['passed'] = False
            result['issues'].append(f'TLS error: {str(e)}')
        except socket.timeout:
            result['passed'] = False
            result['issues'].append('Connection timeout during TLS check')
        except Exception as e:
            result['passed'] = False
            result['issues'].append(f'Connection failed: {str(e)}')

    if result['passed']:
        # CNAME chain analysis
        try:
            cname_answers = dns.resolver.resolve(domain, 'CNAME')
            for rdata in cname_answers:
                cname = str(rdata.target).rstrip('.')
                if levenshtein(domain, cname) > 3:
                    result['passed'] = False
                    result['issues'].append(f'Suspicious CNAME: {cname}')
        except dns.resolver.NoAnswer:
            pass  # No CNAME is fine
        except Exception:
            pass

    # Auto-block if any check failed
    if not result['passed']:
        db = SessionLocal()
        try:
            existing = db.query(BlockedDomain).filter(BlockedDomain.domain == domain).first()
            if not existing:
                db.add(BlockedDomain(domain=domain, reason=', '.join(result['issues'])))
                db.commit()
                # Try to reload dnsmasq so it picks up the new block
                try:
                    subprocess.run(['systemctl', 'reload', 'dnsmasq'], timeout=5)
                except Exception:
                    pass
        finally:
            db.close()

    return result

def detect_typosquat(domain):
    """Check if domain is a typosquat of a popular domain."""
    for popular in POPULAR_DOMAINS:
        dist = levenshtein(domain, popular)
        if dist <= 2 and domain != popular:
            return True, popular
    return False, None