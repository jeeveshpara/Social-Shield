import json
import os
import re
from typing import Any, Dict, Optional
import httpx

from app.services.ai_analyst.prompts import SYSTEM_CYBER_ANALYST_PROMPT, build_analysis_prompt
from app.services.ai_analyst.heuristic_analyst import generate_heuristic_analysis


def _extract_json(text: str) -> Optional[Dict[str, Any]]:
    """Extract and parse JSON from LLM output, handling markdown fences."""
    text = text.strip()
    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", text)
    candidate = match.group(1) if match else text
    try:
        data = json.loads(candidate)
        if isinstance(data, dict) and "executive_summary" in data:
            return data
    except Exception:
        pass
    return None


def call_gemini_free_tier(prompt: str, api_key: str) -> Optional[Dict[str, Any]]:
    """Call Google Gemini Free Tier API (no payment details required)."""
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={api_key}"
    payload = {
        "contents": [
            {
                "role": "user",
                "parts": [{"text": f"{SYSTEM_CYBER_ANALYST_PROMPT}\n\n{prompt}"}],
            }
        ],
        "generationConfig": {
            "temperature": 0.2,
            "responseMimeType": "application/json",
        },
    }
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(url, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                candidates = data.get("candidates", [])
                if candidates:
                    content_text = candidates[0].get("content", {}).get("parts", [{}])[0].get("text", "")
                    parsed = _extract_json(content_text)
                    if parsed:
                        parsed["generated_by"] = "Google Gemini 1.5 Flash (Free Tier)"
                        return parsed
    except Exception:
        pass
    return None


def call_groq_free_tier(prompt: str, api_key: str) -> Optional[Dict[str, Any]]:
    """Call Groq Free Tier API (no payment details required)."""
    url = "https://api.groq.com/openai/v1/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    payload = {
        "model": "llama-3.1-8b-instant",
        "messages": [
            {"role": "system", "content": SYSTEM_CYBER_ANALYST_PROMPT},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.2,
        "response_format": {"type": "json_object"},
    }
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(url, headers=headers, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                content_text = data.get("choices", [{}])[0].get("message", {}).get("content", "")
                parsed = _extract_json(content_text)
                if parsed:
                    parsed["generated_by"] = "Groq LLaMA-3.1 (Free Tier)"
                    return parsed
    except Exception:
        pass
    return None


def generate_ai_security_analysis(
    evidence_bundle: Dict[str, Any],
    risk_score: int,
    risk_level: str,
) -> Dict[str, Any]:
    """
    Generate AI Security Analyst Assessment:
    1. Attempts free cloud LLM (Gemini or Groq) if an API key is present in environment.
    2. Fallback to Autonomous Heuristic Cyber Analyst Engine (100% free, offline, instant).
    """
    gemini_key = os.getenv("GEMINI_API_KEY", "").strip()
    groq_key = os.getenv("GROQ_API_KEY", "").strip()

    prompt = build_analysis_prompt(evidence_bundle, risk_score, risk_level)

    # 1. Try Gemini Free Tier if key is provided
    if gemini_key:
        result = call_gemini_free_tier(prompt, gemini_key)
        if result:
            return result

    # 2. Try Groq Free Tier if key is provided
    if groq_key:
        result = call_groq_free_tier(prompt, groq_key)
        if result:
            return result

    # 3. Always-available Zero-Budget Autonomous Local Analyst
    return generate_heuristic_analysis(evidence_bundle, risk_score, risk_level)
