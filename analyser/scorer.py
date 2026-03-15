from dataclasses import dataclass, field


@dataclass
class RiskResult():
    domain: str
    score: int = 0
    verdict: str = 'LOW'
    signals: list = field(default_factory=list)


def calculate_risk(dns_result, content_result, ssl_result, whois_result, ip_result):
    score = 0
    signals = []

    def add(points, label):
        nonlocal score
        score += points
        signals.append((points, label))

    if dns_result.has_mx:
        add(30, 'MX records present')

    if content_result:
        if content_result.has_login_form:
            add(25, 'Login form detected')
        if content_result.mentions_brand:
            add(20, 'Brand name found on page')
        if content_result.is_parked:
            add(-25, 'Parked domain')

    if ssl_result:
        if not ssl_result.has_ssl:
            add(5, 'No SSL certificate')
        else:
            if ssl_result.is_self_signed:
                add(10, 'Self-signed certificate')
            if ssl_result.is_expired:
                add(5, 'Expired SSL certificate')
            if ssl_result.cert_cn and ssl_result.cert_cn != dns_result.domain:
                brand = dns_result.domain.rsplit('.', 1)[0]
                if brand in ssl_result.cert_cn:
                    add(15, 'SSL certificate mimics original brand')

    if whois_result:
        if whois_result.is_recently_registered:
            add(15, f'Registered {whois_result.days_old} days ago')
        elif whois_result.days_old > 1095:
            add(-10, f'Domain is {whois_result.days_old // 365} years old')

    if ip_result and ip_result.is_flagged:
        add(20, f'IP abuse score: {ip_result.abuse_score}/100')

    score = max(0, min(100, score))

    if score >= 60:
        verdict = 'HIGH'
    elif score >= 30:
        verdict = 'MEDIUM'
    else:
        verdict = 'LOW'

    return RiskResult(
        domain=dns_result.domain,
        score=score,
        verdict=verdict,
        signals=signals
    )