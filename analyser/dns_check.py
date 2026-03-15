from dataclasses import dataclass, field
import dns.resolver
import dns.exception
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.progress import Progress


@dataclass
class DNSResult:
    domain: str
    resolves: bool = False
    has_mx: bool = False
    mx_records: list = field(default_factory=list)
    ip_address: str = ''


def get_resolver():
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ['8.8.8.8', '1.1.1.1', '8.8.4.4']
    resolver.timeout = 3
    resolver.lifetime = 6
    return resolver


RESOLVER = get_resolver()


def check_domain(domain):
    result = DNSResult(domain=domain)

    try:
        answers = RESOLVER.resolve(domain, 'A')
        result.resolves = True
        result.ip_address = str(answers[0])
    except dns.resolver.NXDOMAIN:
        return result
    except dns.resolver.NoAnswer:
        result.resolves = True
    except dns.resolver.Timeout:
        return result
    except dns.exception.DNSException:
        return result

    if result.resolves:
        try:
            mx = RESOLVER.resolve(domain, 'MX')
            result.has_mx = True
            result.mx_records = [str(r) for r in mx]
        except dns.exception.DNSException:
            pass

    return result


def check_all_domains(variants, max_workers=20):
    results = []

    with Progress() as progress:
        task = progress.add_task(
            "[cyan]Checking DNS...",
            total=len(variants)
        )

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = [
                executor.submit(check_domain, v)
                for v in variants
            ]

            for future in as_completed(futures):
                result = future.result()

                if result.resolves:
                    results.append(result)

                progress.advance(task)

    return results