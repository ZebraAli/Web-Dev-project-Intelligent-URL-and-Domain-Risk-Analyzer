"""ThreatScope analysis engine.

Pure-Python heuristics on the URL *string*. It never opens, fetches or
resolves the submitted URL. Every finding carries points; the sum (capped at
100) is the risk score, so each score can be explained by its findings.
"""
import ipaddress
import re
import unicodedata
from urllib.parse import urlsplit, parse_qsl

MAX_LEN = 2048
KEYWORDS = ["login", "signin", "verify", "account", "secure", "update", "banking",
            "password", "confirm", "wallet", "suspend", "invoice", "billing",
            "recover", "unlock", "authenticate", "credential", "payment"]
SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
              "cutt.ly", "rebrand.ly", "shorturl.at", "tiny.cc", "rb.gy", "lnkd.in", "t.ly"}
RISKY_TLDS = {"tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "zip", "mov", "work",
              "support", "country", "kim", "loan", "icu", "cyou", "buzz", "rest", "monster"}
# Multi-part public suffixes (small list; avoids a dependency on a full PSL).
TWO_PART = {"co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "co.in", "net.in",
            "org.in", "ac.in", "gov.in", "co.jp", "com.br", "com.cn", "co.nz", "co.za"}
# Brand -> official registered domains (used for lookalike detection).
BRANDS = {
    "paypal": {"paypal.com"}, "google": {"google.com"}, "microsoft": {"microsoft.com", "live.com"},
    "apple": {"apple.com", "icloud.com"}, "amazon": {"amazon.com", "amazon.in", "amazon.co.uk"},
    "facebook": {"facebook.com"}, "instagram": {"instagram.com"}, "netflix": {"netflix.com"},
    "linkedin": {"linkedin.com"}, "github": {"github.com"}, "whatsapp": {"whatsapp.com"},
    "paytm": {"paytm.com"}, "sbi": {"sbi.co.in", "onlinesbi.sbi"}, "hdfcbank": {"hdfcbank.com"},
    "icicibank": {"icicibank.com"}, "dropbox": {"dropbox.com"}, "binance": {"binance.com"},
}
# Cyrillic/Greek characters that look like Latin letters.
CONFUSABLES = {"а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
               "і": "i", "ѕ": "s", "ј": "j", "һ": "h", "ԁ": "d", "ɡ": "g",
               "ο": "o", "ν": "v", "α": "a", "ρ": "p", "τ": "t", "ι": "i"}
LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "5": "s", "4": "a", "7": "t", "$": "s"})


class InvalidInput(ValueError):
    """Raised with a user-friendly message when the input cannot be analyzed."""


def normalize(raw):
    """Validate and normalize input. Returns (normalized_url, parts, note)."""
    if not isinstance(raw, str) or not raw.strip():
        raise InvalidInput("Enter a URL or domain to analyze.")
    s = raw.strip()
    if len(s) > MAX_LEN:
        raise InvalidInput(f"Input is too long (max {MAX_LEN} characters).")
    if re.search(r"[\s\x00-\x1f]", s):
        raise InvalidInput("Input contains spaces or control characters.")
    note = ""
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.-]*):(//)?", s)
    # "host:port" looks like a scheme; treat it as a bare host if the rest is digits.
    if m and not (m.group(2) or re.match(r"^[^/]+:\d+(/|$)", s)):
        raise InvalidInput(f"Unsupported scheme '{m.group(1)}:'. Only http and https are analyzed.")
    if m and m.group(2):
        if m.group(1).lower() not in ("http", "https"):
            raise InvalidInput(f"Unsupported scheme '{m.group(1)}'. Only http and https are analyzed.")
    else:
        s = "https://" + s.lstrip("/")
        note = "No scheme was given, so https:// was assumed for analysis."
    try:
        p = urlsplit(s)
        host = p.hostname
        port = p.port
    except ValueError:
        raise InvalidInput("This is not a valid URL (malformed host, port or brackets).")
    if not host or len(host) > 253:
        raise InvalidInput("No valid hostname found in the input.")
    host = host.rstrip(".")
    is_ip = _as_ip(host) is not None
    if not is_ip and ("." not in host or any(not l or len(l) > 63 for l in host.split("."))):
        raise InvalidInput("Hostname must be a domain like example.com or an IP address.")
    if re.search(r"[^\w.\-]", host.replace("xn--", ""), re.UNICODE) and not is_ip:
        raise InvalidInput("Hostname contains invalid characters.")
    parts = dict(scheme=p.scheme.lower(), host=host, port=port, netloc=p.netloc, path=p.path,
                 query=p.query, userinfo="@" in p.netloc)
    url = f"{parts['scheme']}://{p.netloc.lower() if not parts['userinfo'] else p.netloc}{p.path or '/'}"
    if p.query:
        url += "?" + p.query
    return url, parts, note


def _as_ip(host):
    """Return an IP object for dotted, decimal, hex or octal-style hosts, else None."""
    try:
        return ipaddress.ip_address(host.strip("[]"))
    except ValueError:
        pass
    try:  # integer / hex forms such as 3232235777 or 0xC0A80001
        n = int(host, 0) if re.fullmatch(r"0x[0-9a-f]+|\d{8,10}", host, re.I) else None
        return ipaddress.ip_address(n) if n is not None and n < 2 ** 32 else None
    except ValueError:
        return None


def split_domain(host):
    """Return (subdomain_labels, registered_domain, tld)."""
    labels = host.split(".")
    n = 3 if ".".join(labels[-2:]) in TWO_PART and len(labels) >= 3 else 2
    n = min(n, len(labels))
    return labels[:-n], ".".join(labels[-n:]), labels[-1]


def _script(ch):
    try:
        return unicodedata.name(ch).split()[0]
    except ValueError:
        return "UNKNOWN"


def _skeleton(label):
    return "".join(CONFUSABLES.get(c, c) for c in label).translate(LEET).replace("rn", "m").replace("vv", "w")


def _edit1(a, b):
    """True if the strings differ by exactly one insert/delete/substitute/swap."""
    if a == b or abs(len(a) - len(b)) > 1:
        return False
    if len(a) == len(b):
        d = [i for i in range(len(a)) if a[i] != b[i]]
        return len(d) == 1 or (len(d) == 2 and d[1] == d[0] + 1 and a[d[0]] == b[d[1]] and a[d[1]] == b[d[0]])
    s, l = sorted((a, b), key=len)
    return any(l[:i] + l[i + 1:] == s for i in range(len(l)))


def _chk(id_, name, status, detail, points=0):
    return dict(id=id_, name=name, status=status, detail=detail, points=points)


def analyze(raw):
    """Run all checks on `raw`. Raises InvalidInput for unusable input."""
    url, p, note = normalize(raw)
    host = p["host"]
    ip = _as_ip(host)
    sub, reg, tld = split_domain(host) if not ip else ([], host, "")
    checks = []

    # 1. HTTPS
    if p["scheme"] == "https":
        checks.append(_chk("https", "HTTPS Usage", "SAFE", "Uses HTTPS (encrypted). This does not prove the site is trustworthy."))
    else:
        checks.append(_chk("https", "HTTPS Usage", "WARN", "Uses plain HTTP; traffic and any entered data are not encrypted.", 10))

    # 2. Length
    n = len(url)
    if n > 150:
        checks.append(_chk("length", "URL Length", "DANGER", f"{n} characters - very long URLs often hide the real destination.", 12))
    elif n > 75:
        checks.append(_chk("length", "URL Length", "WARN", f"{n} characters - longer than typical.", 5))
    else:
        checks.append(_chk("length", "URL Length", "SAFE", f"{n} characters - normal length."))

    # 3. Keywords (hostname hits weigh more than path hits)
    low_host, low_rest = host.lower(), (p["path"] + "?" + p["query"]).lower()
    in_host = [k for k in KEYWORDS if k in low_host]
    in_rest = [k for k in KEYWORDS if k in low_rest and k not in in_host]
    pts = min(24, len(in_host) * 8 + len(in_rest) * 4)
    if not pts:
        checks.append(_chk("keywords", "Suspicious Keywords", "SAFE", "No credential/phishing-style keywords found."))
    else:
        where = ", ".join(in_host + in_rest)
        checks.append(_chk("keywords", "Suspicious Keywords", "DANGER" if pts >= 16 else "WARN",
                           f"Found: {where}. Phishing links often imitate account or security pages.", pts))

    # 4. IP address
    if ip:
        kind = "private/local" if ip.is_private else "public"
        checks.append(_chk("ip", "IP Address Detection", "DANGER", f"Host is a raw {kind} IP address ({ip}) instead of a domain name.", 25))
    else:
        checks.append(_chk("ip", "IP Address Detection", "SAFE", "Uses a domain name, not a raw IP address."))

    # 5. Subdomain depth
    d = len(sub)
    if d >= 4:
        checks.append(_chk("subdomain", "Subdomain Depth", "DANGER", f"{d} subdomain levels - used to bury a fake brand name before the real domain.", 14))
    elif d >= 3:
        checks.append(_chk("subdomain", "Subdomain Depth", "WARN", f"{d} subdomain levels - deeper than usual.", 7))
    else:
        checks.append(_chk("subdomain", "Subdomain Depth", "SAFE", f"{d} subdomain level(s) - normal."))

    # 6. Shortener
    if reg in SHORTENERS:
        checks.append(_chk("shortener", "URL Shortener Detection", "WARN", f"{reg} is a link shortener; the final destination is hidden.", 12))
    else:
        checks.append(_chk("shortener", "URL Shortener Detection", "SAFE", "Not a known URL shortener."))

    # 7. @ symbol (text before @ in the authority is ignored by browsers)
    if p["userinfo"]:
        checks.append(_chk("at", "@ Symbol Detection", "DANGER", f"'@' in the address: the browser actually goes to '{host}', not what appears before the @.", 20))
    elif "@" in p["path"] + p["query"]:
        checks.append(_chk("at", "@ Symbol Detection", "WARN", "'@' appears in the path/query; usually harmless but worth a look.", 3))
    else:
        checks.append(_chk("at", "@ Symbol Detection", "SAFE", "No '@' symbol in the address."))

    # 8. Domain character pattern
    label = reg.split(".")[0] if not ip else ""
    pat, pts = [], 0
    if label and not label.startswith("xn--"):
        if label.count("-") >= 3:
            pat.append(f"{label.count('-')} hyphens"); pts += 6
        elif label.count("-") == 2:
            pat.append("2 hyphens"); pts += 3
        if re.search(r"\d", label) and re.search(r"[a-z]", label) and sum(c.isdigit() for c in label) >= 3:
            pat.append("many digits mixed with letters"); pts += 5
        if len(label) > 25:
            pat.append(f"very long name ({len(label)} chars)"); pts += 4
        if re.search(r"[bcdfghjklmnpqrstvwxz]{6,}", label):
            pat.append("random-looking consonant run"); pts += 5
    if pat:
        checks.append(_chk("pattern", "Domain Character Pattern", "WARN", "Unusual: " + ", ".join(pat) + ".", min(pts, 12)))
    else:
        checks.append(_chk("pattern", "Domain Character Pattern", "SAFE", "Domain name looks conventional."))

    # 9. TLD
    if tld in RISKY_TLDS:
        checks.append(_chk("tld", "Top-Level Domain Analysis", "WARN", f".{tld} is frequently abused for cheap throw-away sites (many legitimate sites exist too).", 10))
    elif ip:
        checks.append(_chk("tld", "Top-Level Domain Analysis", "WARN", "No TLD: host is an IP address.", 0))
    else:
        checks.append(_chk("tld", "Top-Level Domain Analysis", "SAFE", f".{tld} is not on the higher-risk TLD list."))

    # 10. Homograph / punycode / lookalike
    checks.append(_homograph(host, reg, ip))

    findings = [c for c in checks if c["points"]]
    score = min(100, sum(c["points"] for c in findings))
    # Combination bonus: lookalike brand + credential keywords is a classic phishing shape.
    combo = 0
    if any(c["id"] == "homograph" and c["points"] >= 25 for c in checks) and any(c["id"] == "keywords" and c["points"] for c in checks):
        combo = 10
        score = min(100, score + combo)
    return dict(
        input=raw.strip(), normalized_url=url, note=note,
        parts=dict(scheme=p["scheme"], hostname=host, domain=reg, subdomain=".".join(sub) or None,
                   path=p["path"] or "/", port=p["port"], query_params=dict(parse_qsl(p["query"], keep_blank_values=True)[:20])),
        score=score, level=level_for(score), checks=checks,
        explanation=_explain(findings, combo, score), combo_bonus=combo,
    )


def _homograph(host, reg, ip):
    name = "Homograph Attack Detection"
    if ip:
        return _chk("homograph", name, "SAFE", "Not applicable to IP-based hosts.")
    msgs, pts = [], 0
    labels = host.split(".")
    decoded = []
    for l in labels:
        if l.startswith("xn--"):
            try:
                decoded.append(l.encode().decode("idna"))
            except UnicodeError:
                decoded.append(l)
        else:
            decoded.append(l)
    uni = ".".join(decoded)
    if any(l.startswith("xn--") for l in labels):
        msgs.append(f"Punycode (IDN) domain, displays as '{uni}'"); pts += 15
    for l in decoded:  # mixed scripts inside one label is the strongest homograph signal
        scripts = {_script(c) for c in l if c.isalpha()}
        if len(scripts) > 1:
            msgs.append(f"label '{l}' mixes scripts ({', '.join(sorted(scripts))})"); pts += 25; break
    non_ascii = [c for c in uni if ord(c) > 127]
    if non_ascii and pts < 25 and any(c in CONFUSABLES for c in non_ascii):
        msgs.append("contains characters that look like Latin letters"); pts += 15
    # Lookalike of a well-known brand
    label = _skeleton(reg.split(".")[0] if "." in reg else reg)
    raw_label = _skeleton(uni.split(".")[-2]) if uni.count(".") else label
    for brand, official in BRANDS.items():
        if reg in official or uni in official:
            return _chk("homograph", name, "SAFE", f"Official {brand} domain; no homograph or lookalike signs.")
        reg_label = reg.split(".")[0]
        if raw_label == brand and reg_label != brand or label == brand and reg_label != brand:
            msgs.append(f"imitates '{brand}' using look-alike characters"); pts = max(pts, 0) + 25; break
        if _edit1(raw_label, brand) and len(brand) >= 5:
            msgs.append(f"one character away from '{brand}' (typosquatting)"); pts += 25; break
        if brand in raw_label.replace("-", "") and len(raw_label) > len(brand) + 1 and brand in raw_label:
            msgs.append(f"embeds the brand '{brand}' in an unofficial domain"); pts += 18; break
        sub_hit = brand in host.split(".")[:-2] or any(brand in s for s in host.split(".")[:-2])
        if sub_hit:
            msgs.append(f"uses '{brand}' as a subdomain of unrelated domain {reg}"); pts += 18; break
    if not msgs:
        return _chk("homograph", name, "SAFE", "No Unicode, punycode or brand-lookalike patterns found.")
    return _chk("homograph", name, "DANGER" if pts >= 25 else "WARN", "; ".join(msgs).capitalize() + ".", min(pts, 50))


def level_for(score):
    return "LOW" if score < 25 else "MEDIUM" if score < 50 else "HIGH" if score < 75 else "CRITICAL"


def _explain(findings, combo, score):
    if not findings:
        return "No heuristic red flags were found, so the score is 0. This is not proof that the site is safe."
    parts = [f"{c['name']} (+{c['points']})" for c in sorted(findings, key=lambda c: -c["points"])]
    if combo:
        parts.append("Lookalike brand + credential keywords (+10)")
    return (f"Score {score}/100 is the sum of weighted findings, capped at 100: " + "; ".join(parts) +
            ". Each finding is a warning sign, not proof of malicious intent.")


def recommendations(result, intel):
    """Build context-specific advice from the findings."""
    ids = {c["id"]: c for c in result["checks"] if c["points"]}
    r = []
    if intel.get("status") == "listed":
        r.append("URLhaus lists this URL as malicious. Do not open it; report it to whoever sent it.")
    if not ids and intel.get("status") != "listed":
        r.append("No major red flags detected in this scan.")
    if "ip" in ids: r.append("Legitimate services rarely use raw IP addresses. Do not enter credentials here.")
    if "homograph" in ids: r.append("Retype the address yourself or use a bookmark; the domain may imitate a trusted brand.")
    if "shortener" in ids: r.append("Expand the short link with a preview service before opening it.")
    if "at" in ids: r.append("Everything before the '@' is ignored by browsers; the real host is " + result["parts"]["hostname"] + ".")
    if "https" in ids: r.append("Avoid submitting any personal or payment data over an unencrypted HTTP connection.")
    if "keywords" in ids: r.append("Be wary of pages asking you to log in, verify or update an account from a link you were sent.")
    if "subdomain" in ids or "pattern" in ids or "tld" in ids: r.append("Check the registered domain (the part just before the TLD): " + result["parts"]["domain"] + ".")
    if result["level"] in ("HIGH", "CRITICAL"):
        r.append("Avoid entering sensitive information on this website.")
    r.append("Verify the sender or source if you received this link unexpectedly.")
    r.append("If in doubt, contact the organization through its official channels.")
    return r
