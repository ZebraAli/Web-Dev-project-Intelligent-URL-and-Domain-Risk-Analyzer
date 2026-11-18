# ThreatScope — Intelligent URL & Domain Risk Analyzer

Educational cybersecurity tool that scores a URL or domain (0–100) using local heuristics and shows the reasoning behind every point. It **never visits** the submitted site.

## Run
```bash
pip install -r requirements.txt     # only Flask
python app.py                       # open http://127.0.0.1:5000
```

## Structure
```
analyzer.py   heuristics engine (stdlib only): normalize, 10 checks, scoring, recommendations
intel.py      optional URLhaus lookup (never raises, reports honest status)
app.py        Flask API: POST /api/analyze {"url": "..."}
static/       index.html, style.css, app.js (dark dashboard UI)
```

## Scoring
Each finding adds weighted points (e.g. raw IP +25, `@` trick +20, brand lookalike +25, no HTTPS +10, risky TLD +10). Scores are summed and capped at 100; a lookalike + credential keyword combo adds +10.
LOW 0–24 · MEDIUM 25–49 · HIGH 50–74 · CRITICAL 75–100. A warning is a signal, not proof.

## Threat intelligence (optional)
URLhaus now requires a free abuse.ch Auth-Key. Without it the app says so and continues with local checks. To enable: `export URLHAUS_AUTH_KEY=your_key` before `python app.py`. A URLhaus hit raises the score to at least 90. "Not listed" never means "safe".

## Sample URLs
| URL | Expected |
|---|---|
| `https://www.wikipedia.org` | LOW (0) |
| `https://github.com/login` | LOW |
| `bit.ly/abc123` | LOW/MEDIUM, shortener |
| `http://192.168.1.5/login` | MEDIUM, IP + no HTTPS |
| `http://google.com@evil.tk/x` | MEDIUM+, `@` trick |
| `paypa1-secure-login.xyz/verify/account` | HIGH, lookalike + keywords |
| `https://a.b.c.d.e.paypal.evil.com/login` | MEDIUM/HIGH, deep subdomains |
| `https://xn--pypal-4ve.com` | HIGH, punycode homograph |

## Limits
Heuristics only inspect text, so new phishing sites with clean-looking addresses can score low, and some legitimate sites score higher. Short suffix list instead of the full Public Suffix List.
