from dataclasses import dataclass
import whois
from datetime import datetime
import logging

@dataclass
class WHOISResult:
    domain: str
    registered: bool = False
    creation_date: str = ''
    registrar: str = ''
    days_old: int = -1
    is_recently_registered: bool = False


def check_whois(domain):
    result = WHOISResult(domain=domain)
    try:
        w = whois.whois(domain)
        if not w or not w.creation_date:
            return result

        result.registered = True
        result.registrar = str(w.registrar or '')

        cd = w.creation_date
        if isinstance(cd, list):
            cd = cd[0]

        if isinstance(cd, datetime):
            result.creation_date = cd.strftime('%Y-%m-%d')
            result.days_old = (datetime.now() - cd.replace(tzinfo=None)).days
            result.is_recently_registered = result.days_old < 90

    except Exception as e:
        logging.warning(f'WHOIS failed for {domain}: {e}')
    return result