from dataclasses import dataclass
import ssl
import socket
import logging
from datetime import datetime


@dataclass
class SSLResult:
    domain: str
    has_ssl: bool = False
    cert_cn: str = ''
    cert_org: str = ''
    issuer: str = ''
    expiry: str = ''
    is_self_signed: bool = False
    is_expired: bool = False
    is_wildcard: bool = False


def check_ssl(domain):
    result = SSLResult(domain=domain)
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                result.has_ssl = True

                subject = dict(x[0] for x in cert.get('subject', []))
                issuer = dict(x[0] for x in cert.get('issuer', []))

                result.cert_cn = subject.get('commonName', '')
                result.is_wildcard = result.cert_cn.startswith('*')
                result.cert_org = subject.get('organizationName', '')
                result.issuer = issuer.get('organizationName', '')

                expiry_str = cert.get('notAfter', '')
                if expiry_str:
                    expiry = datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                    result.expiry = expiry.strftime('%Y-%m-%d')
                    result.is_expired = expiry < datetime.now()

                result.is_self_signed = (
                    result.cert_cn == result.issuer or
                    result.cert_org == result.issuer
                )
    except Exception as e:
        logging.warning(f'SSL check failed for {domain}: {e}')
    return result