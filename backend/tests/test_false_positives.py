import pytest
from app.services.osint.coordinator import run_osint_pipeline


def test_benign_username_no_false_positive():
    benign_targets = [
        "john_developer",
        "alice_researcher",
        "linux_coder",
    ]
    for target in benign_targets:
        res = run_osint_pipeline(target)
        # Benign accounts should NOT trigger false HIGH/CRITICAL alarms
        assert res["risk_level"] in ["INFO", "LOW"], (
            f"False positive alert on benign target '{target}': got {res['risk_level']} ({res['risk_score']})"
        )


def test_legitimate_platform_url_no_false_positive():
    legit_urls = [
        "https://github.com",
        "https://google.com",
    ]
    for url in legit_urls:
        res = run_osint_pipeline(url)
        assert res["risk_level"] in ["INFO", "LOW"], (
            f"False positive alert on legitimate platform '{url}': got {res['risk_level']} ({res['risk_score']})"
        )


def test_malicious_target_accurate_escalation():
    malicious_targets = [
        "http://paypal-security-update.xyz/login.php?claim=airdrop",
        "http://metamask-doubler-wallet-sync.top/seed-phrase",
    ]
    for target in malicious_targets:
        res = run_osint_pipeline(target)
        assert res["risk_level"] in ["MEDIUM", "HIGH", "CRITICAL"], (
            f"Under-detection on malicious target '{target}': got {res['risk_level']} ({res['risk_score']})"
        )
        assert res["risk_score"] >= 40
