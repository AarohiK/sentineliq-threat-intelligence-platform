# SentinelIQ: Threat Intelligence & IOC Risk Analysis Platform

SentinelIQ is a FastAPI-based threat intelligence platform that automates Indicator of Compromise (IOC) investigation by enriching security indicators through VirusTotal and generating explainable risk assessments.

The project demonstrates security engineering concepts including threat intelligence automation, API security, JWT-based authentication, and backend service design.

---

## Features

### IOC Investigation & Enrichment

SentinelIQ supports automated investigation of:

- IP addresses
- Domains
- URLs
- File hashes

The platform integrates with the VirusTotal API to collect threat intelligence data including:

- Malicious detection counts
- Suspicious detection counts
- Reputation scores
- Threat tags
- ASN information
- Organization details
- Country information

---

## Risk Scoring Engine

SentinelIQ includes a custom risk scoring engine that evaluates threat intelligence data and produces:

- Numerical risk score (0-100)
- Risk classification:
  - High
  - Medium
  - Low
  - Unknown
- Explainable reasoning behind the assigned risk level

Example response:

```json
{
  "ioc": "example.com",
  "type": "domain",
  "riskscore": {
    "risk_score": 85,
    "risk_level": "High",
    "reasons": [
      "Multiple malicious detections found"
    ]
  }
}
