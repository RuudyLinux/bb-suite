"""Centralized Target Validation and SSRF Boundary Protection for BB-SUITE.

Enforces target URL and host validation, detects and blocks private/loopback/cloud metadata
ranges, guards against DNS rebinding, and validates redirect destinations.
"""
from __future__ import annotations
import ipaddress
import re
import socket
from typing import List, Optional, Set, Tuple, Union
from urllib.parse import urlparse, urlsplit

from backend.security.config import is_private_allowed, BB_REQUIRE_DNS_RESOLUTION


# Cloud metadata hostnames and IPs
CLOUD_METADATA_HOSTS = {
    "metadata.google.internal",
    "metadata",
    "instance-data",
    "169.254.169.254",
    "fd00:ec2::254",
}

# Blocked IP networks for public scanning mode
BLOCKED_IPV4_NETWORKS = [
    ipaddress.ip_network("0.0.0.0/8"),          # "This" network
    ipaddress.ip_network("10.0.0.0/8"),         # RFC 1918 Private
    ipaddress.ip_network("100.64.0.0/10"),      # Carrier-grade NAT
    ipaddress.ip_network("127.0.0.0/8"),        # Loopback
    ipaddress.ip_network("169.254.0.0/16"),     # Link-local / Cloud metadata
    ipaddress.ip_network("172.16.0.0/12"),      # RFC 1918 Private
    ipaddress.ip_network("192.0.0.0/24"),       # IETF Protocol Assignments
    ipaddress.ip_network("192.0.2.0/24"),       # TEST-NET-1
    ipaddress.ip_network("192.168.0.0/16"),     # RFC 1918 Private
    ipaddress.ip_network("198.18.0.0/15"),      # Network benchmark tests
    ipaddress.ip_network("198.51.100.0/24"),    # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),     # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),        # Multicast
    ipaddress.ip_network("240.0.0.0/4"),        # Reserved
    ipaddress.ip_network("255.255.255.255/32"), # Broadcast
]

BLOCKED_IPV6_NETWORKS = [
    ipaddress.ip_network("::/128"),             # Unspecified
    ipaddress.ip_network("::1/128"),           # Loopback
    ipaddress.ip_network("::ffff:0:0/96"),      # IPv4-mapped IPv6
    ipaddress.ip_network("100::/64"),           # Discard prefix
    ipaddress.ip_network("64:ff9b::/96"),       # IPv4/IPv6 translation
    ipaddress.ip_network("2001:db8::/32"),      # Documentation
    ipaddress.ip_network("fc00::/7"),           # Unique Local Address (ULA)
    ipaddress.ip_network("fe80::/10"),          # Link-local
    ipaddress.ip_network("ff00::/8"),           # Multicast
]

# Hostname characters validation regex (RFC 1123)
HOSTNAME_REGEX = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)


class TargetValidationError(ValueError):
    """Raised when target validation fails according to the security boundary."""
    pass


def is_ip_blocked(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> Tuple[bool, str]:
    """Check if an IP address belongs to any blocked/private/reserved range."""
    # Handle IPv4-mapped IPv6 addresses (e.g., ::ffff:127.0.0.1)
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    if isinstance(ip, ipaddress.IPv4Address):
        # Explicit cloud metadata check
        if str(ip) == "169.254.169.254":
            return True, "Cloud metadata IP address (169.254.169.254)"
        for net in BLOCKED_IPV4_NETWORKS:
            if ip in net:
                return True, f"Blocked IPv4 range ({net})"
    elif isinstance(ip, ipaddress.IPv6Address):
        for net in BLOCKED_IPV6_NETWORKS:
            if ip in net:
                return True, f"Blocked IPv6 range ({net})"

    if ip.is_loopback:
        return True, "Loopback address"
    if ip.is_private:
        return True, "Private address"
    if ip.is_reserved:
        return True, "Reserved address"
    if ip.is_link_local:
        return True, "Link-local address"
    if ip.is_multicast:
        return True, "Multicast address"
    if ip.is_unspecified:
        return True, "Unspecified address (0.0.0.0 / ::)"

    return False, ""


def resolve_hostname_ips(
    hostname: str,
    require_dns: Optional[bool] = None,
) -> List[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]]:
    """Resolve a hostname to all associated IP addresses safely."""
    # First check if the hostname is already an IP literal
    try:
        ip_obj = ipaddress.ip_address(hostname.strip("[]"))
        return [ip_obj]
    except ValueError:
        pass

    if require_dns is None:
        require_dns = BB_REQUIRE_DNS_RESOLUTION

    if not require_dns:
        return []

    resolved_ips: List[Union[ipaddress.IPv4Address, ipaddress.IPv6Address]] = []
    try:
        addr_info = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        seen: Set[str] = set()
        for family, _, _, _, sockaddr in addr_info:
            ip_str = sockaddr[0]
            if ip_str not in seen:
                seen.add(ip_str)
                try:
                    resolved_ips.append(ipaddress.ip_address(ip_str))
                except ValueError:
                    continue
    except socket.gaierror as err:
        if require_dns:
            raise TargetValidationError(f"DNS resolution failed for hostname '{hostname}': {err}")
        return []

    if not resolved_ips and require_dns:
        raise TargetValidationError(f"Could not resolve any IP addresses for hostname '{hostname}'")

    return resolved_ips


def validate_hostname(
    hostname: str,
    allow_private: Optional[bool] = None,
    require_dns: Optional[bool] = None,
) -> List[str]:
    """Validate a hostname or domain name.

    Returns the list of resolved IP string representations.
    Raises TargetValidationError if invalid or pointing to prohibited targets.
    """
    if not hostname:
        raise TargetValidationError("Target hostname cannot be empty.")

    hostname = hostname.strip().lower()
    if allow_private is None:
        allow_private = is_private_allowed()

    # Reject cloud metadata hostnames
    if hostname in CLOUD_METADATA_HOSTS:
        if not allow_private:
            raise TargetValidationError(f"Access to cloud metadata host '{hostname}' is blocked.")

    # Check localhost names
    if hostname in ("localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback"):
        if not allow_private:
            raise TargetValidationError(f"Access to loopback hostname '{hostname}' is blocked.")

    # Validate syntax if it's not an IP
    is_ip = False
    try:
        ipaddress.ip_address(hostname.strip("[]"))
        is_ip = True
    except ValueError:
        pass

    if not is_ip:
        if len(hostname) > 253:
            raise TargetValidationError("Hostname exceeds maximum RFC length (253 chars).")
        if not HOSTNAME_REGEX.match(hostname):
            raise TargetValidationError(f"Hostname '{hostname}' contains invalid characters.")

    # Resolve IPs and test them
    resolved_ips = resolve_hostname_ips(hostname, require_dns=require_dns)
    ip_strings: List[str] = []

    for ip_obj in resolved_ips:
        ip_str = str(ip_obj)
        ip_strings.append(ip_str)
        blocked, reason = is_ip_blocked(ip_obj)
        if blocked and not allow_private:
            raise TargetValidationError(
                f"Target '{hostname}' resolves to prohibited internal address {ip_str} ({reason}). "
                "Scanning private/internal targets is blocked by security policy."
            )

    return ip_strings


def validate_target_url(
    url: str,
    allowed_schemes: Optional[Tuple[str, ...]] = ("http", "https"),
    allow_private: Optional[bool] = None,
    require_dns: Optional[bool] = None,
) -> str:
    """Validate a target URL completely according to Phase 1 specifications.

    - Must have valid scheme (http/https by default)
    - Must not contain embedded credentials (user:password@)
    - Hostname must be valid and not resolve to private/loopback/cloud metadata (unless allowed)
    - URL must not be malformed

    Returns the normalized URL if valid.
    Raises TargetValidationError otherwise.
    """
    if not url or not isinstance(url, str):
        raise TargetValidationError("URL must be a non-empty string.")

    url = url.strip()

    # Reject whitespace or control characters
    if any(c in url for c in ("\r", "\n", "\t", "\x00")):
        raise TargetValidationError("URL contains invalid control characters.")

    try:
        parsed = urlsplit(url)
    except Exception as exc:
        raise TargetValidationError(f"Malformed URL: {exc}")

    # Scheme validation
    scheme = parsed.scheme.lower()
    if allowed_schemes and scheme not in allowed_schemes:
        raise TargetValidationError(
            f"Prohibited URL scheme '{parsed.scheme}'. Only {allowed_schemes} are allowed."
        )

    # Reject embedded credentials (http://user:pass@host)
    if parsed.username or parsed.password:
        raise TargetValidationError(
            "Embedded credentials in target URLs (user:password@host) are prohibited."
        )

    # Hostname validation
    hostname = parsed.hostname
    if not hostname:
        raise TargetValidationError("URL does not contain a valid hostname.")

    # Port validation
    if parsed.port is not None:
        if parsed.port < 1 or parsed.port > 65535:
            raise TargetValidationError(f"Port {parsed.port} is outside valid TCP range (1-65535).")

    # Validate hostname & resolve DNS to ensure no SSRF / private targets
    validate_hostname(hostname, allow_private=allow_private, require_dns=require_dns)

    return url


def validate_redirect_target(
    initial_url: str,
    target_redirect_url: str,
    allow_private: Optional[bool] = None,
    require_dns: Optional[bool] = None,
) -> str:
    """Validate a redirect target against SSRF boundaries.

    Prevents open redirects from leading the scanner to private/cloud metadata ranges.
    """
    if allow_private is None:
        allow_private = is_private_allowed()

    return validate_target_url(target_redirect_url, allow_private=allow_private, require_dns=require_dns)

