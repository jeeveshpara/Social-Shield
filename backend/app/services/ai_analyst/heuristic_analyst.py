from typing import Any, Dict, List


def generate_heuristic_analysis(
    evidence_bundle: Dict[str, Any],
    risk_score: int,
    risk_level: str,
) -> Dict[str, Any]:
    """
    Autonomous Heuristic Cyber Analyst Engine (Zero-Budget, 100% Free, Offline).
    Correlates multi-source OSINT and Fraud telemetry into structured cyber intelligence
    with MITRE ATT&CK mappings, threat actor profiling, and defensive incident response.
    """
    target = evidence_bundle.get("target", "Target")
    input_type = evidence_bundle.get("input_type", "unknown")
    platform = evidence_bundle.get("platform", "unknown")

    fraud_intel = evidence_bundle.get("fraud_intel", {})
    scam_info = fraud_intel.get("scam_assessment", {})
    phishing_info = fraud_intel.get("phishing_assessment", {})
    impersonation_info = fraud_intel.get("impersonation_assessment", {})
    risk_breakdown = fraud_intel.get("risk_breakdown", {})

    url_trace = evidence_bundle.get("url_trace", {})
    domain_intel = evidence_bundle.get("domain_intel", {})
    username_intel = evidence_bundle.get("username_intel", {})

    # 1. Synthesize Key Findings & MITRE ATT&CK Techniques
    mitre_techniques: List[Dict[str, str]] = []
    evidence_bullets: List[str] = []
    containment_steps: List[str] = []
    recommendations: List[str] = []

    # Check Phishing
    if phishing_info.get("is_suspect") or phishing_info.get("score", 0) >= 30:
        mitre_techniques.append({
            "id": "T1566.002",
            "name": "Phishing: Spearphishing Link",
            "tactic": "Initial Access",
            "description": "Adversary distributes malicious links to trick users into divulging credentials or sensitive tokens.",
        })
        if phishing_info.get("matched_brand"):
            mitre_techniques.append({
                "id": "T1583.001",
                "name": "Acquire Infrastructure: Domains",
                "tactic": "Resource Development",
                "description": f"Domain or subdomains acquired to mimic brand '{phishing_info['matched_brand']}'.",
            })
            evidence_bullets.append(
                f"Typosquatting / brand spoofing detected targeting '{phishing_info['matched_brand']}'."
            )
        containment_steps.append("Block domain across enterprise DNS and secure web gateways (SWG).")
        containment_steps.append("Reset credentials immediately if any authentication data was submitted.")

    # Check Threat Feed Confirmation
    reputation = url_trace.get("reputation", {})
    if reputation.get("status") == "matched":
        mitre_techniques.append({
            "id": "T1204.001",
            "name": "User Execution: Malicious Link",
            "tactic": "Execution",
            "description": "Adversary relies on user clicking confirmed malicious link cataloged by threat feeds.",
        })
        evidence_bullets.append(
            f"Global threat intelligence feed ({reputation.get('provider')}) confirmed malicious activity ({', '.join(reputation.get('threat_types', []))})."
        )
        containment_steps.append("Add URL to firewall deny-lists and submit threat report to registrar abuse contact.")

    # Check Scam Indicators
    matched_scams = scam_info.get("matched_categories", [])
    if matched_scams:
        for cat in matched_scams:
            evidence_bullets.append(
                f"Active fraudulent solicitation identified: {cat.get('title')} ({len(cat.get('matches', []))} matched triggers)."
            )
        mitre_techniques.append({
            "id": "T1589.001",
            "name": "Gather Victim Identity Information: Credentials",
            "tactic": "Reconnaissance",
            "description": "Fraudulent lure soliciting financial transactions or private secret keys.",
        })
        containment_steps.append("Warn users not to send any funds, cryptocurrency, or private keys to this destination.")

    # Check Impersonation
    if impersonation_info.get("is_suspect") or impersonation_info.get("score", 0) >= 30:
        mitre_techniques.append({
            "id": "T1656",
            "name": "Impersonation",
            "tactic": "Defense Evasion",
            "description": "Adversary mimics a trusted authority, executive, or customer service representative.",
        })
        if impersonation_info.get("matched_target"):
            evidence_bullets.append(
                f"Profile mimicry of known high-profile entity: '{impersonation_info['matched_target']}'."
            )

    # Check Homoglyphs
    homoglyphs = username_intel.get("homoglyphs", []) if username_intel else []
    if homoglyphs:
        mitre_techniques.append({
            "id": "T1036.007",
            "name": "Masquerading: Double File Extension or Homoglyph",
            "tactic": "Defense Evasion",
            "description": f"Use of {len(homoglyphs)} lookalike Cyrillic or Unicode characters to deceive visual inspection.",
        })
        evidence_bullets.append(
            f"Target uses {len(homoglyphs)} visual homoglyphs (lookalike Unicode characters)."
        )

    # Check Domain Age / RDAP
    rdap = domain_intel.get("rdap", {}) if domain_intel else {}
    if rdap.get("age_days") is not None and rdap["age_days"] < 30:
        evidence_bullets.append(
            f"Newly registered domain (created {rdap['age_days']} days ago via {rdap.get('registrar', 'registrar')})."
        )
        containment_steps.append("Implement automated quarantine for newly observed domains (<30 days old).")

    # Check Redirects
    redirect_chain = url_trace.get("redirect_chain", []) if url_trace else []
    if len(redirect_chain) > 1:
        evidence_bullets.append(
            f"URL redirect chain spans {len(redirect_chain)} hops, routing to {url_trace.get('final_url')}."
        )

    # If no threats found
    if not evidence_bullets:
        evidence_bullets.append("No active indicators of compromise or fraud heuristics matched the inspected parameters.")
        recommendations.append("Continue baseline monitoring and standard hygiene.")

    # 2. Determine Threat Actor Profile
    if risk_score >= 85:
        intent = "Targeted Credential Harvesting / Direct Financial Exfiltration"
        sophistication = "Advanced" if len(mitre_techniques) >= 3 else "Moderate"
        target_demographic = "Crypto asset holders, banking customers, or enterprise employees"
    elif risk_score >= 65:
        intent = "Social Engineering & Credential Harvesting"
        sophistication = "Moderate"
        target_demographic = "General social media consumers and web users"
    elif risk_score >= 40:
        intent = "Suspicious Traffic Generation / Potential Phishing Staging"
        sophistication = "Low"
        target_demographic = "Unspecified web visitors"
    else:
        intent = "Low Risk / Standard Information Sharing"
        sophistication = "Low"
        target_demographic = "General Public"

    # 3. Construct Executive Summary
    if risk_level in ["CRITICAL", "HIGH"]:
        executive_summary = (
            f"SocialShield AI security assessment identifies '{target}' as a {risk_level}-risk "
            f"threat entity (Composite Risk Score: {risk_score}/100). Telemetry analysis highlights active "
            f"indicators of {intent.lower()} leveraging deceptive presentation and malicious infrastructure. "
            f"Immediate protective containment is advised to prevent account takeover, credential exposure, "
            f"or financial loss."
        )
    elif risk_level == "MEDIUM":
        executive_summary = (
            f"Assessment of '{target}' indicates a MEDIUM security risk posture (Composite Risk Score: {risk_score}/100). "
            f"Several anomaly signals were detected, including unverified domain configurations or authority claims. "
            f"Users should exercise caution and verify authentic origins before disclosing data."
        )
    else:
        executive_summary = (
            f"Defensive intelligence evaluation for '{target}' concluded with a {risk_level} risk score of {risk_score}/100. "
            f"No malicious threat intelligence matches or high-severity social engineering signals were identified "
            f"in the public telemetry."
        )

    # 4. Long-term Recommendations
    recommendations.append("Enforce hardware-bound Multi-Factor Authentication (FIDO2 / WebAuthn) resistant to phishing proxies.")
    recommendations.append("Report fraudulent entities to IC3 (Internet Crime Complaint Center) and Google Safe Browsing.")
    recommendations.append("Verify social media handles exclusively through verified badges or primary official websites.")

    return {
        "executive_summary": executive_summary,
        "threat_actor_profile": {
            "intent": intent,
            "sophistication": sophistication,
            "target_demographic": target_demographic,
        },
        "mitre_attack": mitre_techniques,
        "evidence_synthesis": evidence_bullets,
        "containment_steps": containment_steps if containment_steps else ["No active containment required for baseline low-risk profile."],
        "recommendations": recommendations,
        "generated_by": "SocialShield Autonomous Heuristic Engine (Zero-Budget, Offline)",
    }
