import socket
import ipaddress


def check_domain(domain: str):
    try:
        # Remove protocol if the user enters a full URL
        domain = domain.replace("https://", "").replace("http://", "")
        domain = domain.split("/")[0]

        # Resolve domain to IP address
        ip_address = socket.gethostbyname(domain)

        # Check whether the returned value is a valid IP
        ip_type = "IPv6" if ipaddress.ip_address(ip_address).version == 6 else "IPv4"

        return {
            "status": "success",
            "domain": domain,
            "ip_address": ip_address,
            "ip_type": ip_type,
            "hostname": socket.getfqdn(domain),
            "dns_resolved": True
        }

    except socket.gaierror:
        return {
            "status": "error",
            "dns_resolved": False,
            "error": "Unable to resolve domain"
        }

    except Exception as error:
        return {
            "status": "error",
            "dns_resolved": False,
            "error": str(error)
        }