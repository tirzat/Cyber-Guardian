def calculate_security_score(ssl_result, headers_result, domain_result):

    score = 0
    breakdown = {}

    # 1. HTTPS / SSL - 30 points
    if (
        ssl_result.get("https") is True
        and ssl_result.get("status") == "secure"
    ):
        days_remaining = ssl_result.get("days_remaining")

        if days_remaining is not None and days_remaining < 30:
            ssl_score = 20
        else:
            ssl_score = 30
    else:
        ssl_score = 0

    score += ssl_score
    breakdown["ssl_https"] = ssl_score

    # 2. Security Headers - 40 points
    headers_checked = headers_result.get("headers_checked", 0)
    headers_present = headers_result.get("headers_present", 0)

    if headers_checked > 0:
        header_score = round(
            (headers_present / headers_checked) * 40
        )
    else:
        header_score = 0

    score += header_score
    breakdown["security_headers"] = header_score

    # 3. Domain / DNS - 20 points
    if domain_result.get("dns_resolved") is True:
        domain_score = 20
    else:
        domain_score = 0

    score += domain_score
    breakdown["domain_dns"] = domain_score

    # 4. Website Availability - 10 points
    http_status = headers_result.get("http_status", 0)

    if (
        headers_result.get("status") == "success"
        and 200 <= http_status < 400
    ):
        availability_score = 10
    else:
        availability_score = 0

    score += availability_score
    breakdown["availability"] = availability_score

    # Security rating
    if score >= 80:
        rating = "Good"
    elif score >= 60:
        rating = "Moderate"
    elif score >= 40:
        rating = "Weak"
    else:
        rating = "Critical"

    return {
        "score": score,
        "max_score": 100,
        "rating": rating,
        "breakdown": breakdown
    }