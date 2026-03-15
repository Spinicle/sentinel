import json
from pathlib import Path
import schedule
import time
from rich.console import Console


console = Console()

STATE_DIR = Path('.sentinel_state')

def load_state(target_domain):
    STATE_DIR.mkdir(exist_ok=True)
    state_file = STATE_DIR / f'{target_domain.replace(".", "_")}.json'
    if state_file.exists():
        with open(state_file) as f:
            return set(json.load(f).get('seen_domains', []))
    return set()


def save_state(target_domain, domains):
    STATE_DIR.mkdir(exist_ok=True)
    state_file = STATE_DIR / f'{target_domain.replace(".", "_")}.json'
    with open(state_file, 'w') as f:
        json.dump({'seen_domains': list(domains)}, f, indent=2)


def find_new_domains(current_results, previous_domains):
    current_domains = {r.domain for r in current_results}
    new_domains = current_domains - previous_domains
    return [r for r in current_results if r.domain in new_domains]


def run_scheduled_scan(target_domain, min_score=30):
    from generator.mutations import generate_all
    from analyser.dns_check import check_all_domains
    from analyser.ssl_check import check_ssl
    from analyser.whois_check import check_whois
    from analyser.ip_reputation import check_ip_reputation
    from analyser.scorer import calculate_risk

    console.print(f'[dim]Running scheduled scan for {target_domain}...[/dim]')

    previous = load_state(target_domain)
    variants = generate_all(target_domain)
    live = check_all_domains(variants)

    results = []
    for dns_r in live:
        ssl_r = check_ssl(dns_r.domain)
        whois_r = check_whois(dns_r.domain)
        ip_r = check_ip_reputation(dns_r.ip_address)
        risk = calculate_risk(dns_r, None, ssl_r, whois_r, ip_r)
        if risk.score >= min_score:
            results.append(risk)

    new_findings = find_new_domains(results, previous)

    if new_findings:
        console.print(f'[bold red]ALERT: {len(new_findings)} new domain(s) detected![/]')
        for r in new_findings:
            console.print(f'  [red]{r.verdict}[/] {r.domain} (score: {r.score})')
    else:
        console.print('[green]No new domains detected.[/green]')

    save_state(target_domain, {r.domain for r in results})


def start_monitor(target_domain, interval_hours=24, min_score=30):
    console.print(f'[cyan]Monitoring {target_domain} every {interval_hours}h[/cyan]')
    console.print('[dim]Press Ctrl+C to stop[/dim]\n')

    run_scheduled_scan(target_domain, min_score)

    schedule.every(interval_hours).hours.do(
        run_scheduled_scan, target_domain, min_score)

    try:
        while True:
            schedule.run_pending()
            time.sleep(60)
    except KeyboardInterrupt:
        console.print('\n[yellow]Monitoring stopped.[/yellow]')