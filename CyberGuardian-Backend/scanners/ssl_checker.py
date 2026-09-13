import socket
import ssl
from datetime import datetime


def check_ssl(domain: str):
    try:
        context = ssl.create_default_context()

        with socket.create_connection((domain, 443), timeout=10) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as secure_sock:

                certificate = secure_sock.getpeercert()

                tls_version = secure_sock.version()

                issuer = certificate.get("issuer")
                subject = certificate.get("subject")

                expiry_date = certificate.get("notAfter")

                if expiry_date:
                    expiry_datetime = datetime.strptime(
                        expiry_date,
                        "%b %d %H:%M:%S %Y %Z"
                    )

                    days_remaining = (
                        expiry_datetime - datetime.utcnow()
                    ).days
                else:
                    days_remaining = None

                return {
                    "status": "secure",
                    "https": True,
                    "tls_version": tls_version,
                    "issuer": issuer,
                    "subject": subject,
                    "expiry_date": expiry_date,
                    "days_remaining": days_remaining
                }

    except Exception as error:
        return {
            "status": "error",
            "https": False,
            "error": str(error)
        }