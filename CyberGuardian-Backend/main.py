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
    get_scan_history
)

from utils.url_validator import extract_domain


# --------------------------------------------------
# Create FastAPI application
# --------------------------------------------------

app = FastAPI(title="CyberGuardian API")


# --------------------------------------------------
# CORS Configuration
# Allows the Lovable frontend to communicate
# with the backend during local development.
# --------------------------------------------------

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# --------------------------------------------------
# Create database when backend starts
# --------------------------------------------------

create_database()


# --------------------------------------------------
# Home / Backend Status
# --------------------------------------------------

@app.get("/")
def home():
    return {
        "message": "CyberGuardian Backend is Running!"
    }


# --------------------------------------------------
# SSL / HTTPS Check
# --------------------------------------------------

@app.get("/ssl-check")
def ssl_check(domain: str):

    clean_domain = extract_domain(domain)

    if not clean_domain:
        return {
            "status": "error",
            "message": "Please enter a valid website URL or domain."
        }

    return check_ssl(clean_domain)


# --------------------------------------------------
# Security Headers Check
# --------------------------------------------------

@app.get("/headers-check")
def headers_check(domain: str):

    clean_domain = extract_domain(domain)

    if not clean_domain:
        return {
            "status": "error",
            "message": "Please enter a valid website URL or domain."
        }

    return check_security_headers(clean_domain)


# --------------------------------------------------
# Domain / DNS Check
# --------------------------------------------------

@app.get("/domain-check")
def domain_check(domain: str):

    clean_domain = extract_domain(domain)

    if not clean_domain:
        return {
            "status": "error",
            "message": "Please enter a valid website URL or domain."
        }

    return check_domain(clean_domain)


# --------------------------------------------------
# Security Score
# --------------------------------------------------

@app.get("/score-check")
def score_check(domain: str):

    clean_domain = extract_domain(domain)

    if not clean_domain:
        return {
            "status": "error",
            "message": "Please enter a valid website URL or domain."
        }

    ssl_result = check_ssl(clean_domain)
    headers_result = check_security_headers(clean_domain)
    domain_result = check_domain(clean_domain)

    return calculate_security_score(
        ssl_result,
        headers_result,
        domain_result
    )


# --------------------------------------------------
# Security Recommendations
# --------------------------------------------------

@app.get("/recommendations")
def recommendations(domain: str):

    clean_domain = extract_domain(domain)

    if not clean_domain:
        return {
            "status": "error",
            "message": "Please enter a valid website URL or domain."
        }

    ssl_result = check_ssl(clean_domain)
    headers_result = check_security_headers(clean_domain)
    domain_result = check_domain(clean_domain)

    return generate_recommendations(
        ssl_result,
        headers_result,
        domain_result
    )


# --------------------------------------------------
# Complete Cybersecurity Report
# --------------------------------------------------

@app.get("/full-report")
def full_report(domain: str):

    clean_domain = extract_domain(domain)

    if not clean_domain:
        return {
            "status": "error",
            "message": "Please enter a valid website URL or domain."
        }

    # Use the cleaned domain
    domain = clean_domain

    # SSL / HTTPS scan
    ssl_result = check_ssl(domain)

    # Security headers scan
    headers_result = check_security_headers(domain)

    # Domain / DNS scan
    domain_result = check_domain(domain)

    # Calculate security score
    score_result = calculate_security_score(
        ssl_result,
        headers_result,
        domain_result
    )

    # Generate recommendations
    recommendation_result = generate_recommendations(
        ssl_result,
        headers_result,
        domain_result
    )

    # Save scan to database
    save_scan(
        domain,
        score_result["score"],
        score_result["rating"]
    )

    # Return complete security report
    return {
        "status": "success",
        "domain": domain,
        "ssl": ssl_result,
        "security_headers": headers_result,
        "domain_information": domain_result,
        "security_score": score_result,
        "recommendations": recommendation_result
    }


# --------------------------------------------------
# Scan History
# --------------------------------------------------

@app.get("/history")
def history():

    return get_scan_history()