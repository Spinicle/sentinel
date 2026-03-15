# Sentinel 🔍
A CLI tool that scans for typosquatting domains targeting your brand — finds registered lookalikes before attackers use them.

## What is this?

Brand impersonation is a real problem. Attackers register domains like `razorpay-login.com` or `raz0rpay.com`, slap a fake login page on them, and start phishing your users. Commercial tools that monitor this cost thousands a month.

Sentinel does the same core job for free. You give it a domain, it generates every plausible typo and lookalike variant, checks which ones are actually registered, and scores each one by how dangerous it looks.

## Features

- **Variant generation** — character omissions, transpositions, homoglyphs, keyboard adjacency, TLD swaps, and common word insertions like `-login`, `-secure`, `-pay`
- **DNS resolution** — concurrent checking across all variants, filters down to only registered domains
- **MX record detection** — flags domains that can send phishing emails
- **Content analysis** — visits live domains and checks for login forms, brand mentions, and parked page indicators
- **SSL inspection** — detects self-signed certs, expired certs, and certificates mimicking your brand
- **WHOIS age check** — flags recently registered domains (under 90 days old)
- **IP reputation** — cross-references IPs against AbuseIPDB's community threat database
- **Risk scoring** — combines all signals into a 0-100 score with LOW / MEDIUM / HIGH verdict
- **Multiple output formats** — terminal report, JSON export, CSV export
- **Monitoring mode** — runs on a schedule and alerts only on newly discovered domains
- **Bulk scanning** — scan multiple domains from a text file

## Installation

```bash
# Clone the repo
git clone https://github.com/yourusername/sentinel.git
cd sentinel

# Create and activate a virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Mac/Linux

# Install dependencies
pip install -r requirements.txt

# Set up your AbuseIPDB API key (free at abuseipdb.com)
cp .env.example .env
# Edit .env and add your key
```

## Usage

```bash
# Basic scan
python main.py --domain razorpay.com

# Fast scan (skip content checks)
python main.py --domain razorpay.com --skip-content

# Show counts only
python main.py --domain razorpay.com --count

# Export to JSON and CSV
python main.py --domain razorpay.com --output all

# Only show medium risk and above
python main.py --domain razorpay.com --min-score 30

# Monitor a domain every 24 hours
python main.py --domain razorpay.com --monitor --interval 24

# Scan multiple domains from a file
python main.py --domain placeholder.com --bulk domains.txt
```

## Architecture

Sentinel is built in four layers that run in sequence:

**Generation Layer** — takes your domain and produces every plausible typo and lookalike variant using seven mutation types. For a typical domain this produces 150-200 candidates.

**Analysis Layer** — runs each live domain through DNS resolution, content fetching, SSL inspection, WHOIS lookup, and IP reputation checking. Each check contributes signals to the risk score.

**Scoring Engine** — combines all signals into a single 0-100 risk score. MX records carry the most weight (+30) since they indicate email capability — the primary tool for phishing.

**Output Layer** — presents results as a rich terminal report, machine-readable JSON, or a stakeholder-friendly CSV.

## Known Limitations

- JavaScript-heavy pages won't be fully analysed — `requests` doesn't execute JS. Selenium integration is a future improvement.
- WHOIS data is unreliable for some TLDs, especially Indian ones like `.in` and `.co.in`. Failed lookups are logged to `sentinel.log`.
- IP reputation requires a free AbuseIPDB API key. Without it, IP checks are skipped gracefully.
- The tool produces a risk score, not a definitive verdict. Human review is always the final step.

## Roadmap

- `--whitelist` flag to exclude domains the company already owns
- `--verbose` flag for detailed signal breakdown with point values
- WHOIS ownership transfer detection — flag old domains with recent updates
- Email alerting for monitoring mode
- VirusTotal API integration as an additional reputation source
- Selenium support for JavaScript-heavy pages

## Disclaimer

Sentinel is built for defensive security research and brand protection. Only scan domains relevant to brands you own or have explicit written permission to test. The author is not responsible for misuse.

## License

MIT