from generator.tlds import COMMON_TLDS
import tldextract


HOMOGLYPHS = {
    "a": ["@", "4"], "e": ["3"], "i": ["1", "l"], "l": ["1", "i"], "o": ["0"],
    "s": ["5"], "t": ["7"], "g": ["9"], "b": ["6"], "rn": ["m"], "m": ["rn"]
}

KEYBOARD_ADJACENT = {
    "a": "sqwz", "b": "vghn", "c": "xdfv", "d": "serfcx",
    "e": "wsdr", "f": "drtgcv", "g": "ftyhbv", "h": "gyujnb",
    "i": "ujko", "j": "huikm", "k": "jiolm", "l": "kop",
    "m": "njk", "n": "bhjm", "o": "iklp", "p": "ol",
    "q": "wa", "r": "edft", "s": "awedxz", "t": "rfgy",
    "u": "yhji", "v": "cfgb", "w": "qase", "x": "zsdc",
    "y": "tghu", "z": "asx"
}

INSERTION_WORDS = [
    "login", "secure", "verify", "account", "update",
    "banking", "app", "online", "india", "pay", "portal",
    "official", "my", "support", "help", "safe", "bank",
    "web", "net", "home", "user", "customer", "service",
    "mobile", "access", "signin", "signup", "auth",
    "payment", "wallet", "transfer", "confirm", "alert",
    "notice", "info", "mail", "connect", "go", "get"
]


def omission(domain: str) -> list:
    results = []

    for i in range(len(domain)):
        variant = domain[:i] + domain[i+1:]

        if len(variant) >= 3: # minimum length guard
            results.append(variant)

    return results


def transposition(domain: str) -> list:
    results = []

    for i in range(len(domain) - 1):
        chars = list(domain)

        chars[i], chars[i+1] = chars[i+1], chars[i]

        results.append("".join(chars))

    return results


def homoglyph_substitution(domain: str) -> list:
    results = []

    for i, char in enumerate(domain):
        if char in HOMOGLYPHS:
            for sub in HOMOGLYPHS[char]:
                results.append(domain[:i] + sub + domain[i+1:])

    for i in range(len(domain) - 1):
        pair = domain[i:i+2]

        if pair in HOMOGLYPHS:
            results.append(domain[:i] + HOMOGLYPHS[pair][0] + domain[i+2:])

    return results


def repetition(domain: str) -> list:
    results = []

    for i, char in enumerate(domain):
        results.append(domain[:i] + char + domain[i:])

    return results


def keyboard_adjacency(domain: str) -> list:
    results = []

    for i, char in enumerate(domain):
        if char in KEYBOARD_ADJACENT:
            for neighbour in KEYBOARD_ADJACENT[char]:
                results.append(domain[:i] + neighbour + domain[i+1:])

    return results


def tld_variations(domain: str, original_tld: str) -> list:
    return [
        f"{domain}.{tld}"
        for tld in COMMON_TLDS
        if tld != original_tld
    ]


def insertion(domain: str) -> list:
    results = []

    for word in INSERTION_WORDS:
        results.append(f"{domain}-{word}")
        results.append(f"{word}-{domain}")
        results.append(f"{domain}{word}")

    return results


# MASTER FUNCTION
def generate_all(fqdn: str) -> list:
    is_prefix = False
    fqdn = fqdn.lower().strip().rstrip("/").removeprefix("https://").removeprefix("http://")

    if not fqdn.isascii():
        raise ValueError("Non-ASCII characters detected")

    extracted = tldextract.extract(fqdn)
    domain = extracted.domain
    tld = extracted.suffix
    prefix = extracted.subdomain

    if not domain or not tld:
        raise ValueError(f"Invalid domain format: {fqdn}")

    is_prefix = prefix != ''

    variants = set()

    for v in (
        omission(domain)
        + transposition(domain)
        + homoglyph_substitution(domain)
        + repetition(domain)
        + keyboard_adjacency(domain)
        + insertion(domain)
    ):
        if len(v) >= 3:
            if not is_prefix:
                variants.add(f"{v}.{tld}")
            else:
                variants.add(f"{prefix}.{v}.{tld}")

    for v in tld_variations(domain, tld):
        if not is_prefix:
                variants.add(f"{v}")
        else:
            variants.add(f"{prefix}.{v}")

    variants.discard(fqdn)  # never include original

    return sorted(list(variants))