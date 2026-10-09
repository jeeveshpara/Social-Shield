from typing import Any, Dict, List
from datetime import datetime, timezone

from app.services.analyzer import normalize_input
from app.services.osint.username_analyzer import analyze_username
from app.services.osint.domain_analyzer import analyze_domain
from app.services.osint.url_analyzer import analyze_url
from app.services.osint.metadata_extractor import extract_public_metadata
from app.services.fraud import run_fraud_assessment
from app.services.ai_analyst import generate_ai_security_analysis


def run_osint_pipeline(raw_input: str) -> Dict[str, Any]:
    """
    Master Intelligence Pipeline orchestrating:
      - Sprint 3: OSINT Engine (Username, Domain, DNS, RDAP, URL trace, OpenGraph)
      - Sprint 4: Fraud Engine (Scam indicators, Phishing detection, Impersonation, Calibrated scoring)
    """
    normalized_item = normalize_input(raw_input)
    input_type = normalized_item["input_type"]
    target = normalized_item["normalized"]
    platform = normalized_item["platform"]

    findings: List[Dict[str, Any]] = []
    evidence_bundle: Dict[str, Any] = {
        "target": target,
        "input_type": input_type,
        "platform": platform,
        "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
    }

    text_corpus_parts = [target]
    bio_text = None
    homoglyphs = None
    threat_intel_result = None
    domain_age_days = None
    hostname = None

    if input_type == "username":
        # 1. OSINT Username Intelligence
        username_intel = analyze_username(target, run_probes=True)
        findings.extend(username_intel.get("findings", []))
        homoglyphs = username_intel.get("homoglyphs", [])

        evidence_bundle["username_intel"] = {
            "username": username_intel["username"],
            "entropy": username_intel["entropy"],
            "homoglyphs": username_intel["homoglyphs"],
            "impersonation_terms": username_intel["impersonation_terms"],
            "footprint": username_intel["footprint"],
        }

    else:
        # 2. OSINT URL & Redirection Analysis
        url_intel = analyze_url(target, trace_chain=True)
        findings.extend(url_intel.get("findings", []))
        final_url = url_intel.get("final_url", target)
        text_corpus_parts.append(final_url)

        threat_intel_result = url_intel.get("reputation")
        evidence_bundle["url_trace"] = {
            "initial_url": target,
            "final_url": final_url,
            "is_shortener": url_intel.get("is_shortener", False),
            "redirect_chain": url_intel.get("trace", {}).get("redirect_chain", []),
            "reputation": threat_intel_result,
        }

        # 3. OSINT Domain & DNS Intelligence
        hostname = url_intel.get("host") or normalized_item.get("host")
        if hostname:
            domain_intel = analyze_domain(hostname)
            findings.extend(domain_intel.get("findings", []))
            domain_age_days = domain_intel.get("rdap", {}).get("age_days")

            evidence_bundle["domain_intel"] = {
                "hostname": domain_intel["hostname"],
                "apex_domain": domain_intel["apex_domain"],
                "tld": domain_intel["tld"],
                "dns": domain_intel["dns"],
                "rdap": domain_intel["rdap"],
            }

        # 4. OSINT Public Profile / Web Page Metadata
        meta_result = extract_public_metadata(final_url)
        findings.extend(meta_result.get("findings", []))
        metadata = meta_result.get("metadata", {})
        evidence_bundle["metadata"] = metadata

        if metadata.get("title"):
            text_corpus_parts.append(metadata["title"])
        if metadata.get("description"):
            text_corpus_parts.append(metadata["description"])
            bio_text = metadata["description"]

    # 5. Sprint 4: Unified Fraud Engine Assessment
    fraud_res = run_fraud_assessment(
        target=target,
        input_type=input_type,
        text_corpus=" ".join(text_corpus_parts),
        hostname=hostname,
        bio_text=bio_text,
        homoglyphs=homoglyphs,
        threat_intel_result=threat_intel_result,
        domain_age_days=domain_age_days,
        osint_findings=findings,
    )

    # Merge fraud findings
    findings.extend(fraud_res["fraud_findings"])
    evidence_bundle["fraud_intel"] = fraud_res["fraud_evidence"]

    calibrated = fraud_res["calibrated_risk"]
    risk_score = calibrated["score"]
    risk_level = calibrated["level"]

    # 6. Sprint 5: AI Security Analyst Assessment (Evidence-based correlation & MITRE mapping)
    ai_report = generate_ai_security_analysis(
        evidence_bundle=evidence_bundle,
        risk_score=risk_score,
        risk_level=risk_level,
    )
    evidence_bundle["ai_analyst"] = ai_report

    return {
        "target": target,
        "input_type": input_type,
        "platform": platform,
        "risk_score": risk_score,
        "risk_level": risk_level,
        "findings": findings,
        "evidence": evidence_bundle,
        "analysis_scope": (
            "SocialShield Defensive Intelligence Engine: Multi-layered OSINT & Fraud analysis "
            "synthesized using zero-cost public endpoints, open DNS/RDAP standards, heuristic "
            "scam & phishing classifiers, and multi-factor risk calibration. "
            "Zero paid APIs or billing credentials required."
        ),
    }
