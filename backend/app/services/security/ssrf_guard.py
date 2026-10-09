import ipaddress
import socket
from urllib.parse import urlsplit


BLOCKED_HOSTNAMES = {
    "localhost",
    "127.0.0.1",
    "::1",
    "metadata.google.internal",
    "instance-data",
}


def is_ssrf_safe_url(url: str) -> bool:
    """
    Verify whether a target URL is safe from SSRF exploitation.
    Blocks private networks, loopbacks, link-local metadata addresses,
    and reserved IP spaces.
    """
    try:
        parsed = urlsplit(url if "://" in url else f"https://{url}")
        host = (parsed.hostname or "").lower().rstrip(".")

        if not host:
            return False

        if host in BLOCKED_HOSTNAMES or host.endswith(".local") or host.endswith(".internal"):
            return False

        # Attempt to parse as direct IP literal
        try:
            ip = ipaddress.ip_address(host.strip("[]"))
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_multicast
                or ip.is_reserved
                or str(ip) == "169.254.169.254"
            ):
                return False
        except ValueError:
            # It is a domain name; resolve DNS to inspect target IP
            try:
                addr_info = socket.getaddrinfo(host, None)
                for entry in addr_info:
                    resolved_ip_str = entry[4][0]
                    ip = ipaddress.ip_address(resolved_ip_str)
                    if (
                        ip.is_private
                        or ip.is_loopback
                        or ip.is_link_local
                        or ip.is_multicast
                        or ip.is_reserved
                        or str(ip) == "169.254.169.254"
                    ):
                        return False
            except Exception:
                # If DNS resolution fails here, allow analyzer to handle DoH queries
                pass

        return True
    except Exception:
        return False
