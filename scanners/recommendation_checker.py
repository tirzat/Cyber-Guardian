def generate_recommendations(
    ssl_result,
    headers_result,
    domain_result
):
    recommendations = []

    # SSL / HTTPS recommendation
    if ssl_result.get("https") is not True:
        recommendations.append({
            "severity": "High",
            "issue": "HTTPS is not properly secured",
            "recommendation": "Enable HTTPS and install a valid SSL/TLS certificate."
        })
    else:
        recommendations.append({
            "severity": "Info",
            "issue": "HTTPS is enabled",
            "recommendation": "Continue using HTTPS and keep the TLS certificate valid."
        })

    # SSL certificate expiry
    days_remaining = ssl_result.get("days_remaining")

    if days_remaining is not None and days_remaining < 30:
        recommendations.append({
            "severity": "High",
            "issue": "SSL certificate is expiring soon",
            "recommendation": "Renew the SSL/TLS certificate before it expires."
        })

    # Security headers
    header_results = headers_result.get("results", {})

    for header, details in header_results.items():

        if not details.get("present"):
            recommendations.append({
                "severity": "Medium",
                "issue": f"{header} is missing",
                "recommendation": f"Consider configuring the {header} security header."
            })

    # DNS
    if domain_result.get("dns_resolved") is not True:
        recommendations.append({
            "severity": "High",
            "issue": "DNS resolution failed",
            "recommendation": "Check the domain's DNS configuration."
        })
    else:
        recommendations.append({
            "severity": "Info",
            "issue": "Domain resolved successfully",
            "recommendation": "DNS resolution is working correctly."
        })

    return {
        "status": "success",
        "recommendations": recommendations,
        "total_recommendations": len(recommendations)
    }