import click
import logging
from rich.console import Console
from rich.progress import Progress
from datetime import datetime
import os

from generator.mutations import generate_all
from analyser.dns_check import check_all_domains
from analyser.content_check import analyse_content
from analyser.ssl_check import check_ssl
from analyser.whois_check import check_whois
from analyser.ip_reputation import check_ip_reputation
from analyser.scorer import calculate_risk
from output.terminal import print_full_report
from output.json_export import export_json
from output.csv_export import export_csv
from analyser.ip_reputation import _rate_limited

logging.basicConfig(
    filename='sentinel.log',
    level=logging.WARNING,
    format='%(asctime)s %(levelname)s %(message)s'
)

console = Console()


@click.command()
@click.option('--domain', '-d', default=None, help='Target domain e.g. razorpay.com')
@click.option('--output', '-o', type=click.Choice(['terminal', 'json', 'csv', 'all']), default='terminal', help='Output format')
@click.option('--outfile', '-f', default=None, help='Output file path')
@click.option('--skip-dns', is_flag=True, help='Skip DNS checking (generation only)')
@click.option('--skip-content', is_flag=True, help='Skip HTTP content checks (faster)')
@click.option('--min-score', default=0, help='Only show results above this score')
@click.option('--count', is_flag=True, help='Print counts only')
@click.option('--monitor', is_flag=True, help='Run in continuous monitoring mode')
@click.option('--interval', default=24, help='Hours between scans (default: 24)')
@click.option('--bulk', '-b', default=None, help='Path to file with one domain per line')
def main(domain, output, outfile, skip_dns, skip_content, min_score, count, monitor, interval, bulk):
    """
    Sentinel — Domain Typosquatting Scanner
    """

    os.makedirs('output_files', exist_ok=True)

    if monitor:
        from monitor.scheduler import start_monitor
        start_monitor(domain, interval_hours=interval, min_score=min_score)
        return

    if not domain and not bulk:
        console.print("[bold red]Error:[/] Provide --domain or --bulk")
        return

    if bulk:
        with open(bulk) as f:
            targets = [line.strip() for line in f if line.strip()]
    else:
        targets = [domain]
    
    for target in targets:
        console.print(f'\n[bold cyan]--- Scanning {target} ---[/bold cyan]')
        domain = target

        # Stage 1: Generate variants
        try:
            variants = generate_all(domain)
        except ValueError as e:
            console.print(f"[bold red]Error:[/] {e}")
            continue

        console.print(f"[dim]Generated {len(variants)} variants[/dim]")

        if skip_dns:
            continue

        # Stage 2: DNS Check
        live = check_all_domains(variants)

        if not live:
            console.print("[green]No registered lookalike domains found.[/green]")
            continue

        console.print(f"[dim]Found {len(live)} live domains[/dim]\n")

        if count:
            console.print(f"[green]Variants: {len(variants)} | Live: {len(live)}[/green]")
            continue

        # Stage 3: Deep analysis
        risk_results = []
        
        try:
            with Progress() as progress:
                task = progress.add_task("[cyan]Analysing domains...", total=len(live))
                for dns_r in live:
                    content_r = analyse_content(dns_r.domain, domain) if not skip_content else None
                    ssl_r = check_ssl(dns_r.domain)
                    whois_r = check_whois(dns_r.domain)
                    ip_r = check_ip_reputation(dns_r.ip_address)
                    risk = calculate_risk(dns_r, content_r, ssl_r, whois_r, ip_r)
                    if risk.score >= min_score:
                        risk_results.append(risk)
                    progress.advance(task)
        except KeyboardInterrupt:
            console.print("\n[yellow]Scan interrupted — showing partial results...[/yellow]")

        if _rate_limited:
            console.print("[bold yellow]⚠ AbuseIPDB daily limit reached — IP reputation checks were skipped for some domains.[/bold yellow]")

        risk_results.sort(key=lambda r: r.score, reverse=True)

        # Stage 4: Output
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        if output in ('terminal', 'all'):
            print_full_report(domain, len(variants), risk_results)

        if output in ('json', 'all'):
            json_path = (outfile.rsplit('.', 1)[0] if outfile else f'output_files/sentinel_{domain}_{timestamp}') + '.json'
            export_json(domain, risk_results, json_path)
            console.print(f"[green]JSON saved to {json_path}[/green]")

        if output in ('csv', 'all'):
            csv_path = (outfile.rsplit('.', 1)[0] if outfile else f'output_files/sentinel_{domain}_{timestamp}') + '.csv'
            export_csv(domain, risk_results, csv_path)
            console.print(f"[green]CSV saved to {csv_path}[/green]")


if __name__ == "__main__":
    main()