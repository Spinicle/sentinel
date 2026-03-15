import csv
from datetime import datetime
import os


def export_csv(target_domain, results, filepath=None):
    os.makedirs('output_files', exist_ok=True)
    
    if not filepath:
        filepath = f'output_files/sentinel_{target_domain}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.csv'

    with open(filepath, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'Domain', 'Risk Score', 'Verdict',
            'MX Records', 'Login Form', 'Brand Mentioned',
            'Recently Registered', 'IP Flagged', 'Key Signals'
        ])
        for r in results:
            has_mx = any('MX' in l for _, l in r.signals)
            has_login = any('Login' in l for _, l in r.signals)
            has_brand = any('Brand' in l for _, l in r.signals)
            recent_reg = any('days ago' in l for _, l in r.signals)
            ip_flag = any('abuse' in l.lower() for _, l in r.signals)
            signals_text = ' | '.join(l for _, l in r.signals if _ > 0)

            writer.writerow([
                r.domain, r.score, r.verdict,
                has_mx, has_login, has_brand,
                recent_reg, ip_flag, signals_text
            ])

    return filepath