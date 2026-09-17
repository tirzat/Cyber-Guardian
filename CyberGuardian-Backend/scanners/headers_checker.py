import requests


# Security-related response headers
SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS",
    "Content-Security-Policy": "Content Security Policy",
    "X-Content-Type-Options": "X-Content-Type-Options",
    "X-Frame-Options": "X-Frame-Options",
    "Referrer-Policy": "Referrer Policy",
    "Permissions-Policy": "Permissions Policy",
    "Cross-Origin-Opener-Policy": "Cross-Origin-Opener-Policy",
    "Cross-Origin-Embedder-Policy": "Cross-Origin-Embedder-Policy",
    "Cross-Origin-Resource-Policy": "Cross-Origin-Resource-Policy",
    "X-XSS-Protection": "X-XSS-Protection",
}


def check_security_headers(domain: str):
    try:

        # --------------------------------------------------
        # Build URL
        # --------------------------------------------------

        if not domain.startswith(("http://", "https://")):
            url = "https://" + domain
        else:
            url = domain

        # --------------------------------------------------
        # Request website
        # --------------------------------------------------

        response = requests.get(
            url,
            timeout=10,
            allow_redirects=True
        )

        headers = response.headers

        # --------------------------------------------------
        # Check security headers
        # --------------------------------------------------

        results = {}

        for header, description in SECURITY_HEADERS.items():

            if header in headers:

                results[header] = {
                    "present": True,
                    "description": description,
                    "value": headers[header]
                }

            else:

                results[header] = {
                    "present": False,
                    "description": description,
                    "value": None
                }

        # --------------------------------------------------
        # Count security headers
        # --------------------------------------------------

        present_count = sum(
            1
            for result in results.values()
            if result["present"]
        )

        total_count = len(SECURITY_HEADERS)

        # --------------------------------------------------
        # Additional public HTTP information
        # --------------------------------------------------

        server_header = headers.get("Server")

        content_type = headers.get("Content-Type")

        content_length = headers.get("Content-Length")

        cache_control = headers.get("Cache-Control")

        pragma = headers.get("Pragma")

        # --------------------------------------------------
        # Return result
        # --------------------------------------------------

        return {
            "status": "success",

            "url": response.url,

            "http_status": response.status_code,

            "headers_present": present_count,

            "headers_checked": total_count,

            "results": results,

            "http_information": {
                "content_type": content_type,
                "server": server_header,
                "content_length": content_length,
                "cache_control": cache_control,
                "pragma": pragma
            }
        }

    except requests.RequestException as error:

        return {
            "status": "error",
            "error": str(error)
        }