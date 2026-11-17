"""Threat-intelligence lookups: VirusTotal v3 and AbuseIPDB v2.

Every provider returns a small, normalised ``Reputation`` so the rest of the
playbook does not depend on any vendor's response format. Lookups fail soft:
an API error is recorded on the result instead of stopping the playbook.
"""

from __future__ import annotations

import base64
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from .entities import Indicator

TIMEOUT_SECONDS = 15


@dataclass
class Reputation:
    provider: str
    indicator: Indicator
    malicious: int = 0          # engines / reports flagging it as malicious
    suspicious: int = 0
    abuse_score: int | None = None   # AbuseIPDB confidence 0-100
    details: dict = field(default_factory=dict)
    error: str | None = None


def _get_json(url: str, headers: dict) -> dict:
    request = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(request, timeout=TIMEOUT_SECONDS) as response:
        return json.loads(response.read().decode("utf-8"))


class VirusTotal:
    name = "virustotal"
    base = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str, fetch=_get_json):
        self.api_key = api_key
        self.fetch = fetch

    def supports(self, ind: Indicator) -> bool:
        return ind.kind in ("url", "filehash") or ind.is_public_ip

    def _path(self, ind: Indicator) -> str:
        if ind.kind == "ip":
            return f"ip_addresses/{ind.value}"
        if ind.kind == "filehash":
            return f"files/{ind.value}"
        url_id = base64.urlsafe_b64encode(ind.value.encode()).decode().rstrip("=")
        return f"urls/{url_id}"

    def lookup(self, ind: Indicator) -> Reputation:
        result = Reputation(self.name, ind)
        try:
            body = self.fetch(f"{self.base}/{self._path(ind)}", {"x-apikey": self.api_key})
        except urllib.error.HTTPError as exc:
            result.error = "not found in VirusTotal" if exc.code == 404 else f"HTTP {exc.code}"
            return result
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            result.error = f"lookup failed: {exc}"
            return result
        attributes = body.get("data", {}).get("attributes", {})
        stats = attributes.get("last_analysis_stats", {})
        result.malicious = int(stats.get("malicious", 0))
        result.suspicious = int(stats.get("suspicious", 0))
        result.details = {
            "stats": stats,
            "reputation": attributes.get("reputation"),
            "country": attributes.get("country"),
            "as_owner": attributes.get("as_owner"),
            "meaningful_name": attributes.get("meaningful_name"),
        }
        return result


class AbuseIPDB:
    name = "abuseipdb"
    base = "https://api.abuseipdb.com/api/v2/check"

    def __init__(self, api_key: str, fetch=_get_json):
        self.api_key = api_key
        self.fetch = fetch

    def supports(self, ind: Indicator) -> bool:
        return ind.is_public_ip

    def lookup(self, ind: Indicator) -> Reputation:
        result = Reputation(self.name, ind)
        query = urllib.parse.urlencode({"ipAddress": ind.value, "maxAgeInDays": 90})
        try:
            body = self.fetch(f"{self.base}?{query}",
                              {"Key": self.api_key, "Accept": "application/json"})
        except urllib.error.HTTPError as exc:
            result.error = f"HTTP {exc.code}"
            return result
        except (urllib.error.URLError, TimeoutError, ValueError) as exc:
            result.error = f"lookup failed: {exc}"
            return result
        data = body.get("data", {})
        result.abuse_score = int(data.get("abuseConfidenceScore", 0))
        result.details = {
            "total_reports": data.get("totalReports"),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "usage_type": data.get("usageType"),
        }
        return result


class FixtureProvider:
    """Offline provider for demos and tests: answers from samples/fixtures/*.json."""

    def __init__(self, name: str, fixture_file: Path, inner_cls):
        self.name = name
        data = json.loads(fixture_file.read_text(encoding="utf-8"))
        self._inner = inner_cls("offline", fetch=self._fetch)
        self._data = data

    def _fetch(self, url: str, headers: dict) -> dict:
        for key, body in self._data.items():
            if key in url:
                return body
        raise urllib.error.HTTPError(url, 404, "not in fixtures", hdrs=None, fp=None)

    def supports(self, ind: Indicator) -> bool:
        # Samples use documentation IP ranges (RFC 5737), which are not globally
        # routable, so offline mode answers for any IP present in the fixtures.
        if ind.kind == "ip":
            return any(ind.value in key for key in self._data)
        return self._inner.supports(ind)

    def lookup(self, ind: Indicator) -> Reputation:
        return self._inner.lookup(ind)
