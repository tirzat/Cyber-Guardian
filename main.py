import os

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from scanners.ssl_checker import check_ssl
from scanners.headers_checker import check_security_headers
from scanners.domain_checker import check_domain
from scanners.score_checker import calculate_security_score
from scanners.recommendation_checker import generate_recommendations

from database import (
    create_database,
    save_scan,
    get_scan_history,
)

from utils.url_validator import extract_domain


# ============================================================
# ENVIRONMENT
# ============================================================

load_dotenv()


# ============================================================
# FASTAPI APPLICATION
# ============================================================

app = FastAPI(
    title="CyberGuardian API",
    description="CyberGuardian website security analysis API",
    version="1.0.0",
)


# ============================================================
# CORS
# ============================================================

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# DATABASE
# ============================================================

create_database()


# ============================================================
# ROOT
# ============================================================

@app.get("/")
def root():
    return {
        "status": "success",
        "message": "CyberGuardian Backend is Running!",
    }


# ============================================================
# SSL CHECK
# ============================================================

@app.get("/ssl-check")
def ssl_check_endpoint(domain: str):

    clean_domain = extract_domain(domain)

    if not clean_domain:
        return {
            "status": "error",
            "message": "Please enter a valid website URL or domain.",
        }

    return check_ssl(clean_domain)


# ============================================================
# SECURITY HEADERS CHECK
# ============================================================

@app.get("/headers-check")
def headers_check_endpoint(domain: str):

    clean_domain = extract_domain(domain)

    if not clean_domain:
        return {
            "status": "error",
            "message": "Please enter a valid website URL or domain.",
        }

    return check_security_headers(clean_domain)


# ============================================================
# DOMAIN / DNS CHECK
# ============================================================

@app.get("/domain-check")
def domain_check_endpoint(domain: str):

    clean_domain = extract_domain(domain)

    if not clean_domain:
        return {
            "status": "error",
            "message": "Please enter a valid website URL or domain.",
        }

    return check_domain(clean_domain)


# ============================================================
# SECURITY SCORE
# ============================================================

@app.get("/score-check")
def score_check_endpoint(domain: str):

    clean_domain = extract_domain(domain)

    if not clean_domain:
        return {
            "status": "error",
            "message": "Please enter a valid website URL or domain.",
        }

    ssl_result = check_ssl(clean_domain)
    headers_result = check_security_headers(clean_domain)
    domain_result = check_domain(clean_domain)

    return calculate_security_score(
        ssl_result,
        headers_result,
        domain_result,
    )


# ============================================================
# SECURITY RECOMMENDATIONS
# ============================================================

@app.get("/recommendations")
def recommendations_endpoint(domain: str):

    clean_domain = extract_domain(domain)

    if not clean_domain:
        return {
            "status": "error",
            "message": "Please enter a valid website URL or domain.",
        }

    ssl_result = check_ssl(clean_domain)
    headers_result = check_security_headers(clean_domain)
    domain_result = check_domain(clean_domain)

    score_result = calculate_security_score(
        ssl_result,
        headers_result,
        domain_result,
    )

    return generate_recommendations(
        ssl_result,
        headers_result,
        domain_result,
        score_result,
    )


# ============================================================
# FULL SECURITY REPORT
# ============================================================

@app.get("/full-report")
def full_report_endpoint(domain: str):

    clean_domain = extract_domain(domain)

    if not clean_domain:
        return {
            "status": "error",
            "message": "Please enter a valid website URL or domain.",
        }

    # Run scanners
    ssl_result = check_ssl(clean_domain)

    headers_result = check_security_headers(clean_domain)

    domain_result = check_domain(clean_domain)

    # Calculate score
    score_result = calculate_security_score(
        ssl_result,
        headers_result,
        domain_result,
    )

    # Generate recommendations
    recommendations_result = generate_recommendations(
        ssl_result,
        headers_result,
        domain_result,
        score_result,
    )

    # Save scan history
    try:

        score = score_result.get("score", 0)

        rating = score_result.get(
            "rating",
            "Unknown",
        )

        save_scan(
            clean_domain,
            score,
            rating,
        )

    except Exception:
        pass

    return {
        "status": "success",
        "domain": clean_domain,
        "ssl": ssl_result,
        "security_headers": headers_result,
        "domain_info": domain_result,
        "security_score": score_result,
        "recommendations": recommendations_result,
    }


# ============================================================
# SCAN HISTORY
# ============================================================

@app.get("/history")
def history_endpoint():

    try:

        history = get_scan_history()

        return {
            "status": "success",
            "history": history,
        }

    except Exception as error:

        return {
            "status": "error",
            "message": str(error),
        }


# ============================================================
# CYBERGUARDIAN SECURITY ASSISTANT
# ============================================================

@app.get("/ai-assistant")
def ai_assistant(question: str):

    # Check empty question
    if not question.strip():

        return {
            "status": "error",
            "message": "Please enter a question.",
        }

    q = question.strip().lower()


    # ========================================================
    # SSL / HTTPS / TLS
    # ========================================================

    if (
        "ssl" in q
        or "tls" in q
        or "certificate" in q
        or "https" in q
    ):

        answer = (
            "SSL/TLS helps protect communication between a website "
            "and its visitors. An SSL certificate helps establish "
            "an encrypted HTTPS connection. CyberGuardian checks "
            "HTTPS availability, SSL status, TLS protocol, certificate "
            "issuer, expiry date, and remaining validity when available."
        )


    # ========================================================
    # SECURITY HEADERS
    # ========================================================

    elif (
        "header" in q
        or "headers" in q
        or "content-security-policy" in q
        or "hsts" in q
    ):

        answer = (
            "Security headers are HTTP response headers that help "
            "protect websites against several browser-based security "
            "risks. CyberGuardian checks security headers such as "
            "Content-Security-Policy, Strict-Transport-Security, "
            "X-Content-Type-Options, X-Frame-Options, Referrer-Policy "
            "and Permissions-Policy."
        )


    # ========================================================
    # SECURITY SCORE
    # ========================================================

    elif (
        "score" in q
        or "rating" in q
        or "low score" in q
    ):

        answer = (
            "The CyberGuardian Security Posture Score is based on "
            "the security checks performed by CyberGuardian. "
            "The current calculation considers SSL/HTTPS, security "
            "headers, domain/DNS information and website availability. "
            "A lower score means that one or more checked areas "
            "may need improvement. The score is not a complete "
            "penetration test and does not guarantee complete security."
        )


    # ========================================================
    # DOMAIN / DNS
    # ========================================================

    elif (
        "domain" in q
        or "dns" in q
        or "ip address" in q
        or "hostname" in q
    ):

        answer = (
            "Domain and DNS information describes how a website "
            "is identified and resolved on the Internet. "
            "CyberGuardian checks information such as the domain, "
            "IP address, hostname and DNS resolution status."
        )


    # ========================================================
    # RECOMMENDATIONS / IMPROVEMENT
    # ========================================================

    elif (
        "recommendation" in q
        or "recommendations" in q
        or "improve" in q
        or "improvement" in q
        or "fix" in q
        or "secure" in q
    ):

        answer = (
            "To improve your CyberGuardian Security Posture Score, "
            "review the recommendations in your report. Common "
            "improvements include using HTTPS, maintaining secure "
            "TLS configuration, adding appropriate security headers, "
            "and maintaining correct domain and DNS configuration."
        )


    # ========================================================
    # REPORT EXPLANATION
    # ========================================================

    elif (
        "report" in q
        or "scan result" in q
        or "scan results" in q
        or "explain my" in q
    ):

        answer = (
            "Your CyberGuardian report summarizes the security checks "
            "performed on the website. Start by reviewing the Security "
            "Posture Score. Then review HTTPS and SSL/TLS, security "
            "headers, domain and DNS information, and finally the "
            "recommendations. The recommendations show areas that "
            "can be improved based on the checks performed."
        )


    # ========================================================
    # GENERAL CYBERSECURITY
    # ========================================================

    elif (
        "cybersecurity" in q
        or "cyber security" in q
    ):

        answer = (
            "Cybersecurity is the practice of protecting systems, "
            "networks, applications and data from unauthorized access "
            "and security threats. Website security includes HTTPS/TLS, "
            "security headers, secure configuration, authentication, "
            "access control and regular security testing."
        )


    # ========================================================
    # DEFAULT ANSWER
    # ========================================================

    else:

        answer = (
            "I am the CyberGuardian Security Assistant. "
            "I can explain SSL/TLS, HTTPS, security headers, "
            "security scores, domain and DNS information, "
            "security recommendations and scan reports. "
            "Try asking: "
            "'Why is my security score low?' or "
            "'What is an SSL certificate?'"
        )


    # ========================================================
    # RESPONSE
    # ========================================================

    return {
        "status": "success",
        "answer": answer,
    }