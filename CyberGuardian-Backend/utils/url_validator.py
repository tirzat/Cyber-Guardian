from urllib.parse import urlparse
import ipaddress
import socket


def is_private_or_internal(hostname: str):
    """
    Block localhost, private IPs, loopback,
    link-local and other internal addresses.
    """

    hostname = hostname.lower().strip("[]")

    # Block obvious local hostnames
    blocked_hostnames = {
        "localhost",
        "localhost.localdomain",
        "ip6-localhost",
        "ip6-loopback",
    }

    if hostname in blocked_hostnames:
        return True

    # If hostname itself is an IP address
    try:
        ip = ipaddress.ip_address(hostname)

        return (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
            or ip.is_unspecified
        )

    except ValueError:
        pass

    # Resolve domain and check resulting IP addresses
    try:
        addresses = socket.getaddrinfo(
            hostname,
            None,
            proto=socket.IPPROTO_TCP
        )

        for address in addresses:
            ip_address = address[4][0]

            try:
                ip = ipaddress.ip_address(ip_address)

                if (
                    ip.is_private
                    or ip.is_loopback
                    or ip.is_link_local
                    or ip.is_reserved
                    or ip.is_multicast
                    or ip.is_unspecified
                ):
                    return True

            except ValueError:
                continue

    except socket.gaierror:
        # DNS failure will be handled by the scanner itself.
        pass

    return False


def normalize_url(url: str):
    url = url.strip()

    if not url:
        return None

    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    if not parsed.netloc:
        return None

    hostname = parsed.hostname

    if not hostname:
        return None

    # Block internal/private targets
    if is_private_or_internal(hostname):
        return None

    return url


def extract_domain(url: str):
    normalized_url = normalize_url(url)

    if not normalized_url:
        return None

    parsed = urlparse(normalized_url)

    return parsed.netloc