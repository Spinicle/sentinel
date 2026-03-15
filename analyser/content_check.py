from dataclasses import dataclass
import requests
import urllib3
import random
from bs4 import BeautifulSoup
import time


@dataclass
class ContentResult:
    domain: str
    reachable: bool = False
    is_parked: bool = False
    has_login_form: bool = False
    mentions_brand: bool = False
    redirects_to_original: bool = False
    page_title: str = ''
    final_url: str = ''
    

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36',
]

PARKED_INDICATORS = [
    'domain for sale', 'buy this domain', 'domain is for sale',
    'parked by', 'this domain is parked', 'godaddy',
    'hugedomains', 'dan.com', 'sedo.com', 'afternic',
    'register this domain', 'domain may be for sale'
]


urllib3.disable_warnings()


def fetch_page(domain):
    headers = {'User-Agent': random.choice(USER_AGENTS)}
    for scheme in ['https', 'http']:
        try:
            url = f'{scheme}://{domain}'
            resp = requests.get(url, headers=headers, timeout=8, allow_redirects=True, verify=False)
            if resp.status_code == 200:
                time.sleep(0.5)
                return resp.text, resp.url
        except requests.RequestException:
            continue
    return None, None


def is_parked(html):
    if not html:
        return False
    text = html.lower()
    return any(indicator in text for indicator in PARKED_INDICATORS)


def has_login_form(html):
    if not html:
        return False
    soup = BeautifulSoup(html, 'html.parser')
    
    if soup.find_all('input', {'type': 'password'}):
        return True
    
    for form in soup.find_all('form'):
        action = (form.get('action') or '').lower()
        if any(word in action for word in ['login', 'signin', 'auth', 'account']):
            return True
    
    return False


def mentions_brand(html, original_domain):
    if not html:
        return False
    brand = original_domain.rsplit('.', 1)[0].lower()
    return brand in html.lower()


def get_page_title(html):
    if not html:
        return ''
    soup = BeautifulSoup(html, 'html.parser')
    title = soup.find('title')
    return title.get_text(strip=True)[:100] if title else ''


def analyse_content(domain, original_domain):
    html, final_url = fetch_page(domain)
    result = ContentResult(domain=domain)
    
    if html is None:
        result.reachable = False
        return result
    elif html == '':
        result.reachable = True
        return result
    
    result.reachable = True
    result.final_url = final_url or ''
    if original_domain in final_url:
        result.redirects_to_original = True
    result.is_parked = is_parked(html)
    result.has_login_form = has_login_form(html)
    result.mentions_brand = mentions_brand(html, original_domain)
    result.page_title = get_page_title(html)
    
    return result