from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box


console = Console()


def verdict_color(verdict):
    return {'HIGH': 'red', 'MEDIUM': 'yellow', 'LOW': 'green'}.get(verdict, 'white')


def print_summary(target_domain, total_variants, total_live, results):
    high = sum(1 for r in results if r.verdict == 'HIGH')
    medium = sum(1 for r in results if r.verdict == 'MEDIUM')
    low = sum(1 for r in results if r.verdict == 'LOW')

    summary = (
        f'Target          : [bold yellow]{target_domain}[/]\n'
        f'Variants checked: {total_variants}\n'
        f'Live domains    : {total_live}\n'
        f'[bold red]HIGH risk       : {high}[/]\n'
        f'[yellow]MEDIUM risk     : {medium}[/]\n'
        f'[green]LOW risk        : {low}[/]'
    )
    console.print(Panel(summary, title='[bold cyan]SENTINEL SCAN REPORT[/]', border_style='cyan'))


def print_results_table(results):
    table = Table(box=box.ROUNDED, show_header=True, header_style='bold cyan')
    table.add_column('Domain', style='white', min_width=30)
    table.add_column('Score', justify='center', width=8)
    table.add_column('Verdict', justify='center', width=10)
    table.add_column('Key Signals', style='dim')

    for r in results:
        color = verdict_color(r.verdict)
        top_signals = ', '.join(label for _, label in r.signals if _ > 0)[:60]
        table.add_row(
            r.domain,
            f'[{color}]{r.score}[/]',
            f'[bold {color}]{r.verdict}[/]',
            top_signals
        )
    console.print(table)


def print_domain_result(result):
    color = verdict_color(result.verdict)
    header = f'[bold {color}][{result.verdict} - {result.score}/100][/] {result.domain}'
    console.print(header)
    for points, label in sorted(result.signals, key=lambda x: x[0], reverse=True):
        if points > 0:
            console.print(f'  [red]●[/red] {label}')
        else:
            console.print(f'  [green]●[/green] {label}')
    console.print()


def print_full_report(target, total_variants, results):
    live = len(results)
    print_summary(target, total_variants, live, results)
    console.print()
    if results:
        print_results_table(results)
        console.print()
        for r in results:
            if r.verdict in ('HIGH', 'MEDIUM'):
                print_domain_result(r)
    else:
        console.print('[green]No registered lookalike domains found.[/green]')