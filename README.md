# 🛡️ CyberGuardian

### Analyze. Protect. Secure.

CyberGuardian is a cybersecurity website analysis application that helps users understand the basic security posture of a website using safe, non-intrusive security checks.

A user enters a website or domain, and CyberGuardian generates a security report containing SSL/TLS information, HTTPS status, security headers, domain/DNS information, a security score, rating, and security recommendations.

---

## 🎯 Project Objective

The objective of CyberGuardian is to provide an easy-to-understand website security analysis tool for students, developers, and users who want to learn about the security configuration of websites.

The application performs passive and safe security checks without exploiting or attacking the target website.

---

## ✨ Main Features

- 🔐 SSL/TLS certificate analysis
- 🌐 HTTPS status checking
- 🛡️ Security header analysis
- 🌍 Domain and DNS information
- 📊 Security score out of 100
- ⭐ Security rating
- 💡 Security recommendations
- 📋 Complete security report
- 🕒 Scan history
- 🤖 AI Security Assistant
- 📱 Responsive web interface
- 📱 Planned Android application

---

## 🔍 Security Checks

### SSL/TLS Analysis

CyberGuardian checks publicly available SSL/TLS information such as:

- HTTPS availability
- TLS version
- Certificate issuer
- Certificate subject
- Certificate expiry date
- Remaining certificate validity

### Security Headers

CyberGuardian checks security-related HTTP response headers including:

- Strict-Transport-Security
- Content-Security-Policy
- X-Content-Type-Options
- X-Frame-Options
- Referrer-Policy
- Permissions-Policy
- Cross-Origin-Opener-Policy
- Cross-Origin-Embedder-Policy
- Cross-Origin-Resource-Policy
- X-XSS-Protection

### Domain and DNS Information

The application checks:

- Domain name
- IP address
- IP type
- Hostname
- DNS resolution status

### Security Score

The website receives a security score from:

**0 to 100**

The current rating categories are:

| Score | Rating |
|---|---|
| 80–100 | Good |
| 60–79 | Moderate |
| 40–59 | Weak |
| 0–39 | Critical |

---

## 🏗️ System Architecture

```text
                ┌─────────────────────┐
                │   CyberGuardian UI  │
                │   Web Frontend      │
                └──────────┬──────────┘
                           │
                           │ REST API
                           ▼
                ┌─────────────────────┐
                │   FastAPI Backend   │
                │      Python         │
                └──────────┬──────────┘
                           │
          ┌────────────────┼────────────────┐
          │                │                │
          ▼                ▼                ▼
     SSL/TLS          HTTP Headers       Domain/DNS
      Scanner            Scanner           Scanner
          │                │                │
          └────────────────┼────────────────┘
                           ▼
                  ┌─────────────────┐
                  │ Security Score  │
                  │ & Recommendations│
                  └────────┬────────┘
                           │
                           ▼
                  ┌─────────────────┐
                  │ SQLite Database  │
                  │  Scan History    │
                  └─────────────────┘ 
