import os

from dotenv import load_dotenv
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from openai import OpenAI

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

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

if OPENAI_API_KEY:
    client = OpenAI(api_key=OPENAI_API_KEY)
else:
    client = None


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
        rating = score_result.get("rating", "Unknown")

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
# AI SECURITY ASSISTANT
# ============================================================

@app.get("/ai-assistant")
def ai_assistant(question: str):

    if not question.strip():
        return {
            "status": "error",
            "message": "Please enter a question.",
        }

    if client is None:
        return {
            "status": "error",
            "message": "OpenAI API key is not configured on the backend.",
        }

    try:

        response = client.responses.create(
            model="gpt-5.6-luna",
            instructions=(
                "You are CyberGuardian AI Security Assistant. "
                "You help users understand website security results "
                "in simple and clear language. "
                "Give defensive cybersecurity guidance only. "
                "Do not provide instructions for malware, credential theft, "
                "unauthorized access, exploitation, bypassing security "
                "controls, or other harmful activity. "
                "Keep answers practical and beginner-friendly."
            ),
            input=question.strip(),
        )

        return {
            "status": "success",
            "answer": response.output_text,
        }

    except Exception as error:

        return {
            "status": "error",
            "message": str(error),
        }