from dataclasses import dataclass
import requests
import os
from dotenv import load_dotenv
import logging


_rate_limited = False

@dataclass
class IPReputationResult:
    ip: str
    abuse_score: int = 0
    total_reports: int = 0
    is_flagged: bool = False
    country: str = ''
    isp: str = ''


load_dotenv()
API_KEY = os.getenv('ABUSEIPDB_API_KEY', '')

_ip_cache = {}


def check_ip_reputation(ip):
    result = IPReputationResult(ip=ip)

    global _rate_limited
    if _rate_limited:
        return result

    if ip in _ip_cache:
        return _ip_cache[ip]
        
    if not API_KEY or not ip:
        return result
    
    if ip.startswith(('192.168.', '10.', '172.', '127.')):
        return result
    
    try:
        response = requests.get(
            'https://api.abuseipdb.com/api/v2/check',
            headers={
                'Accept': 'application/json',
                'Key': API_KEY
            },
            params={
                'ipAddress': ip,
                'maxAgeInDays': 90
            },
            timeout=5
        )
        if response.status_code == 429:
            _rate_limited = True
            logging.warning('AbuseIPDB daily limit reached — IP checks disabled for remainder of scan')
            return result
        
        if response.status_code == 200:
            data = response.json().get('data', {})
            result.abuse_score = data.get('abuseConfidenceScore', 0)
            result.total_reports = data.get('totalReports', 0)
            result.country = data.get('countryCode', '')
            result.isp = data.get('isp', '')
            result.is_flagged = result.abuse_score > 20
    except Exception as e:
        logging.warning(f'IP reputation check failed for {ip}: {e}')
    
    _ip_cache[ip] = result
    return result