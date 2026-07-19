# SentinelIQ: Threat Intelligence & IOC Risk Analysis Platform

## Overview

SentinelIQ is a security-focused threat intelligence platform designed to automate Indicator of Compromise (IOC) investigation workflows.

The platform accepts security indicators such as IP addresses, domains, URLs, and file hashes, enriches them using the VirusTotal API, applies a custom risk scoring engine, and returns explainable threat assessments.

The project demonstrates practical security engineering concepts including:

- Threat intelligence automation
- IOC enrichment
- SOC investigation workflows
- REST API development
- API authentication and authorization
- Identity and access management principles

---

# Features

## IOC Investigation

SentinelIQ analyzes common threat intelligence indicators:

| IOC Type | Example |
| --- | --- |
| IP Address | `8.8.8.8` |
| Domain | `example.com` |
| URL | `https://example.com/login` |
| File Hash | `SHA256 hash` |

The platform automatically identifies IOC types and retrieves threat intelligence data from VirusTotal.

---

## VirusTotal Threat Intelligence Enrichment

SentinelIQ integrates with the VirusTotal API to collect security intelligence including:

- Malicious detection results
- Suspicious detection results
- Reputation scores
- Threat tags
- ASN information
- Organization information
- Country information

---

# Risk Scoring Engine

SentinelIQ includes a custom risk scoring engine that converts threat intelligence findings into an explainable security assessment.

The engine generates:

- Risk score (0-100)
- Risk level classification
- Investigation reasoning

Example response:

```json
{
    "risk_score": 85,
    "risk_level": "High",
    "reasons": [
        "Multiple malicious detections identified"
    ]
}
```

---

# API Security & Authentication

SentinelIQ uses Auth0 (Okta) to protect API endpoints using JWT-based authentication.

Security controls implemented:

- Bearer token authentication
- JWT signature validation
- JWKS public key verification
- Issuer validation
- Audience validation
- Protected API routes

Authentication workflow:

```
Client
  |
  | JWT Access Token
  ↓
FastAPI Endpoint
  |
  ↓
Auth0 Token Verification
  |
  ↓
Authorized API Access
```

Requests without valid authentication tokens are rejected.

---

# API Functionality

## IOC Investigation Endpoint

The platform provides an API endpoint for submitting indicators and receiving threat intelligence assessments.

Example request:

```json
{
    "ioc": "example.com",
    "type": "domain"
}
```

Example response:

```json
{
    "ioc": "example.com",
    "type": "domain",
    "riskscore": {
        "risk_score": 10,
        "risk_level": "Low"
    }
}
```

---

# Database Tracking

SentinelIQ maintains investigation records to support security analysis and tracking.

Stored information includes:

- IOC value
- IOC type
- Risk score
- Risk level
- Investigation timestamp

---

# Technology Stack

## Backend

- Python
- FastAPI
- REST APIs
- Pydantic

## Security

- Auth0 (Okta)
- JWT
- JWKS
- OAuth 2.0 concepts

## Threat Intelligence

- VirusTotal API
- IOC enrichment
- Risk scoring

## Database

- SQLite

---

# Security Concepts Demonstrated

This project demonstrates practical experience with:

- Threat intelligence workflows
- SOC investigation processes
- IOC analysis
- API security
- JWT authentication
- Identity and access management
- Secure backend development
- External security API integration
