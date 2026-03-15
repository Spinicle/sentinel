import json
from datetime import datetime


def export_json(target_domain, results, filepath=None):
    output = {
        'sentinel_version': '1.0',
        'scan_target': target_domain,
        'scan_timestamp': datetime.now().isoformat(),
        'total_results': len(results),
        'high_risk_count': sum(1 for r in results if r.verdict == 'HIGH'),
        'medium_risk_count': sum(1 for r in results if r.verdict == 'MEDIUM'),
        'low_risk_count': sum(1 for r in results if r.verdict == 'LOW'),
        'results': [
            {
                'domain': r.domain,
                'score': r.score,
                'verdict': r.verdict,
                'signals': [{'points': p, 'label': l} for p, l in r.signals]
            }
            for r in results
        ]
    }

    json_str = json.dumps(output, indent=2)

    if filepath:
        with open(filepath, 'w') as f:
            f.write(json_str)
        return filepath

    return json_str