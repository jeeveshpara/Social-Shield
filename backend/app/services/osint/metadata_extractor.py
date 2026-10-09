import ipaddress
import re
from urllib.parse import urlsplit
from typing import Any, Dict, List, Optional
import httpx
from bs4 import BeautifulSoup


# SSRF Guard: Prevent scanning localhost / RFC 1918 private / link-local / loopback networks
def is_safe_external_url(url: str) -> bool:
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        if not hostname:
            return False

        # Disallow localhost / loopback aliases
        if hostname.lower() in {"localhost", "127.0.0.1", "::1"}:
            return False

        try:
            ip = ipaddress.ip_address(hostname.strip("[]"))
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                return False
        except ValueError:
            # Domain name, allowed
            pass

        return True
    except Exception:
        return False


def extract_public_metadata(url: str) -> Dict[str, Any]:
    """
    Safely extract public OpenGraph, Twitter, and standard HTML meta tags.
    Does not authenticate, execute JavaScript, or access private endpoints.
    Enforces SSRF prevention, stream size cap (512KB), and timeout (3.5s).
    """
    if not is_safe_external_url(url):
        return {
            "success": False,
            "error": "URL target resolves to a private or restricted network address.",
            "metadata": {},
            "findings": [],
        }

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) "
            "Chrome/124.0.0.0 Safari/537.36 SocialShield-Defensive/1.0"
        ),
        "Accept": "text/html,application/xhtml+xml",
        "Accept-Language": "en-US,en;q=0.9",
    }

    try:
        with httpx.Client(timeout=3.5, follow_redirects=True) as client:
            with client.stream("GET", url, headers=headers) as resp:
                content_type = resp.headers.get("Content-Type", "").lower()
                if not any(t in content_type for t in ["text/html", "application/xhtml+xml", "text/plain"]):
                    return {
                        "success": False,
                        "error": f"Unsupported Content-Type ({content_type}). Only web pages are parsed.",
                        "metadata": {},
                        "findings": [],
                    }

                # Read at most 512 KB to avoid memory abuse
                max_bytes = 512 * 1024
                chunks = []
                bytes_read = 0
                for chunk in resp.iter_bytes():
                    chunks.append(chunk)
                    bytes_read += len(chunk)
                    if bytes_read >= max_bytes:
                        break

                raw_html = b"".join(chunks).decode(resp.encoding or "utf-8", errors="replace")

        soup = BeautifulSoup(raw_html, "html.parser")

        title = None
        if soup.title and soup.title.string:
            title = soup.title.string.strip()

        meta_tags: Dict[str, str] = {}
        for tag in soup.find_all("meta"):
            name = tag.get("name") or tag.get("property")
            content = tag.get("content")
            if name and content:
                meta_tags[name.strip().lower()] = content.strip()

        canonical_link = None
        canonical_tag = soup.find("link", rel=lambda x: x and "canonical" in x.lower())
        if canonical_tag and canonical_tag.get("href"):
            canonical_link = canonical_tag["href"].strip()

        og_title = meta_tags.get("og:title")
        og_description = meta_tags.get("og:description")
        og_image = meta_tags.get("og:image")
        og_site_name = meta_tags.get("og:site_name")
        og_type = meta_tags.get("og:type")
        twitter_title = meta_tags.get("twitter:title")
        twitter_description = meta_tags.get("twitter:description")
        meta_description = meta_tags.get("description")
        author = meta_tags.get("author")

        metadata_dict = {
            "title": title or og_title or twitter_title,
            "description": og_description or twitter_description or meta_description,
            "og_site_name": og_site_name,
            "og_type": og_type,
            "og_image": og_image,
            "canonical_url": canonical_link,
            "author": author,
        }

        # Analyze extracted metadata for suspicious signals
        findings = []
        combined_text = (
            f"{metadata_dict['title'] or ''} {metadata_dict['description'] or ''}"
        ).lower()

        urgency_terms = ["urgent", "verify immediately", "account suspended", "airdrop claim", "free crypto", "metamask", "seed phrase"]
        matched_urgent = [term for term in urgency_terms if term in combined_text]
        if matched_urgent:
            findings.append({
                "code": "OSINT_METADATA_SUSPICIOUS_PHRASES",
                "severity": "high",
                "points": 25,
                "evidence": f"Web metadata contains social engineering / phishing lures: {', '.join(matched_urgent)}.",
                "recommendation": "Do not enter credentials or cryptographic keys into this site.",
            })

        if not title and not metadata_dict["description"]:
            findings.append({
                "code": "OSINT_METADATA_BLANK_OR_CLOAKED",
                "severity": "low",
                "points": 10,
                "evidence": "Web page returns no title or descriptive meta tags. May indicate a parked, blank, or cloaked page.",
                "recommendation": "Check whether the destination relies on client-side redirect cloaking or is abandoned.",
            })

        return {
            "success": True,
            "metadata": metadata_dict,
            "findings": findings,
        }

    except httpx.TimeoutException:
        return {
            "success": False,
            "error": "HTTP metadata fetch timed out after 3.5s.",
            "metadata": {},
            "findings": [],
        }
    except Exception as exc:
        return {
            "success": False,
            "error": f"Metadata extraction failed: {str(exc)}",
            "metadata": {},
            "findings": [],
        }
