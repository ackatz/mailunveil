async def check(
    spf_record,
    dmarc_record,
    spam_domain,
    phishing_domain,
    disposable_domain,
    new_domain,
    suspicious_tld,
    spoofable,
    deliverable,
    catch_all,
    randomness,
):
    score = 0
    reputation = "neutral"

    # Add more points for SPF and DMARC records and deliverable
    if spf_record:
        score += 2  # Increase points for SPF record
    if dmarc_record:
        score += 2  # Increase points for DMARC record

    # Higher points for strong DMARC policies
    if dmarc_record and ("p=reject" in dmarc_record or "p=quarantine" in dmarc_record):
        score += 2  # Strong DMARC policy

    # Points for DMARC reporting setup
    if dmarc_record and ("rua=" in dmarc_record):
        score += 1  # Aggregate reports set up
    if dmarc_record and ("ruf=" in dmarc_record):
        score += 1  # Forensic reports set up

    score += (
        2 if deliverable else -2
    )  # Increase points for deliverable, penalize undeliverable more

    # Subtract points for negative indicators
    if randomness:
        score -= 2  # Randomness is a strong negative indicator
    if spam_domain:
        score -= 4  # Spam domain carries a heavy penalty
    if phishing_domain:
        score -= 5  # Phishing is treated most severely
    if disposable_domain:
        score -= 3  # Disposable domain is a significant concern
    if new_domain:
        score -= 4  # New domain is a strong negative indicator
    if suspicious_tld:
        score -= 2  # Suspicious TLDs are moderately penalized
    if spoofable:
        score -= 2  # Spoofability is a concern
    if catch_all:
        score -= 1  # Catch-all addresses are a minor concern

    # Adjusted reputation thresholds
    if score >= 10:
        reputation = "excellent"
    elif 5 <= score < 10:
        reputation = "good"
    elif 0 <= score < 5:
        reputation = "neutral"
    elif -5 <= score < 0:
        reputation = "poor"
    else:
        reputation = "awful"

    return reputation, score
