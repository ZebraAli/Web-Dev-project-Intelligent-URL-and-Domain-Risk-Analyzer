"""Optional URLhaus lookup. Never raises; always returns an honest status.

status: not_configured | unreachable | listed | not_listed
URLhaus requires a free abuse.ch Auth-Key (set URLHAUS_AUTH_KEY). Without it
we do NOT pretend a check happened. The submitted URL is only sent as text to
the API; ThreatScope never visits it.
"""
import json
import os
import urllib.parse
import urllib.request

API = "https://urlhaus-api.abuse.ch/v1/url/"


def lookup(url, timeout=4):
    key = os.environ.get("URLHAUS_AUTH_KEY", "").strip()
    if not key:
        return dict(status="not_configured", message="URLhaus is not configured (no URLHAUS_AUTH_KEY set), so no external check was performed. Continuing with local heuristic checks only.")
    try:
        req = urllib.request.Request(API, data=urllib.parse.urlencode({"url": url}).encode(),
                                     headers={"Auth-Key": key}, method="POST")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read(1_000_000))
    except Exception:
        return dict(status="unreachable", message="URLhaus could not be reached or rejected the request. Continuing with local heuristic checks only; this is NOT a confirmation that the URL is clean.")
    if data.get("query_status") == "ok":
        return dict(status="listed", message="URLhaus lists this URL in its malware database.",
                    details=dict(threat=data.get("threat"), url_status=data.get("url_status"),
                                 date_added=data.get("date_added"), tags=data.get("tags") or []))
    if data.get("query_status") == "no_results":
        return dict(status="not_listed", message="URLhaus returned no record for this exact URL. That does not mean it is safe; it may simply be unreported.")
    return dict(status="unreachable", message="URLhaus returned an unexpected response. Continuing with local heuristic checks only.")
