# calculate risk score based on relevant extracted data from 
# virustotal data.

# logic: returns score from 0 to 100, where 0 is safe and 100 is 
# highly malicious. Risk score formula: 
# risk_score = 0.45(malicious_score) + 0.15(suspicious_score) + 0.25(threat_context_score)
# + 0.10(reputation_score) + 0.05(tag_score)


def risk_score(vt_data):
    if vt_data is None:
        return {
            "risk_score": 0,
            "risk_level": "Unknown",
            "reasons": ["No VirusTotal data available"]
        }

    reasons = []

    malicious = vt_data.get("malicious", 0)
    suspicious = vt_data.get("suspicious", 0)
    reputation = vt_data.get("reputation", 0)
    tags = vt_data.get("tags", [])
    threat_context = vt_data.get("threat_context", [])


    # malicious detections 
    malicious_score = min(malicious * 10, 100)

    if malicious > 0:
        reasons.append(
            f"{malicious} security engines detected malicious activity")


    # suspicious detections
    suspicious_score = min(suspicious * 20, 100)

    if suspicious > 0:
        reasons.append(
            f"{suspicious} engines marked IOC as suspicious")


    # crowdsourced threat intelligence
    threat_context_score = 0

    if threat_context:
        threat_context_score += 10
        reasons.append(
            "IOC associated with crowdsourced threat intelligence")

        for threat in threat_context:
            severity = threat.get("severity", "").lower()

            if severity == "high":
                threat_context_score += 30
                reasons.append(
                    "High severity threat intelligence match")

            elif severity == "medium":
                threat_context_score += 15
                reasons.append(
                    "Medium severity threat intelligence match")

            elif severity == "low":
                threat_context_score += 5
                reasons.append(
                    "Low severity threat intelligence match")

    threat_context_score = min(threat_context_score, 100)


    # reputation score
    # negative vt reputation increases risk
    if reputation < 0:
        reputation_score = min(abs(reputation), 100)
        reasons.append(
            "Negative VirusTotal reputation score")
    else:
        reputation_score = 0


    # threat tags
    suspicious_keywords = ["malware",
        "botnet",
        "c2",
        "phishing",
        "ransomware",
        "trojan"]

    tag_score = 0

    for tag in tags:
        if any(keyword in tag.lower() for keyword in suspicious_keywords):
            tag_score += 10
            reasons.append(
                f"Suspicious tag detected: {tag}")

    tag_score = min(tag_score, 100)

    # calc score based on formuala
    score = (
        0.45 * malicious_score
        + 0.15 * suspicious_score
        + 0.25 * threat_context_score
        + 0.10 * reputation_score
        + 0.05 * tag_score)

    score = max(0, min(score, 100))

    # risk classification
    if score >= 70:
        level = "High"
    elif score >= 30:
        level = "Medium"
    else:
        level = "Low"

    return {
        "risk_score": round(score, 2),
        "risk_level": level,
        "reasons": reasons}



