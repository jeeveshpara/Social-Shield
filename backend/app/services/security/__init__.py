"""
SocialShield Security Hardening Package (Sprint 6).
Authentication, RBAC, Rate Limiting, SSRF Protection, and Prompt Injection Defense.
"""

from app.services.security.auth import (
    hash_password,
    verify_password,
    create_access_token,
    decode_access_token,
    seed_default_users,
)
from app.services.security.rbac import get_current_user, require_role
from app.services.security.rate_limiter import rate_limit
from app.services.security.ssrf_guard import is_ssrf_safe_url
from app.services.security.prompt_guard import inspect_and_sanitize_prompt_input

__all__ = [
    "hash_password",
    "verify_password",
    "create_access_token",
    "decode_access_token",
    "seed_default_users",
    "get_current_user",
    "require_role",
    "rate_limit",
    "is_ssrf_safe_url",
    "inspect_and_sanitize_prompt_input",
]
