"""Deterministic scoring and response proposals.

Containment decisions are made here, by plain rules a reviewer can read, and
never by the language model. Every containment action is only *proposed*:
it carries ``requires_approval=True`` and the playbook has no code path that
executes it.
"""

from __future__ import annotations

from dataclasses import dataclass

from .entities import Indicator
from .providers import Reputation

ORDER = ["unknown", "clean", "suspicious", "malicious"]

# Thresholds - tune them per client maturity and noise level.
VT_MALICIOUS = 5        # engines flagging malicious
VT_SUSPICIOUS = 1
ABUSE_MALICIOUS = 75    # AbuseIPDB confidence score
ABUSE_SUSPICIOUS = 25


@dataclass
class IndicatorVerdict:
    indicator: Indicator
    verdict: str
    reasons: list[str]


@dataclass
class ProposedAction:
    action: str
    target: str
    reason: str
    requires_approval: bool


def score_indicator(indicator: Indicator, reputations: list[Reputation]) -> IndicatorVerdict:
    verdict, reasons = "unknown", []

    def raise_to(level: str, reason: str):
        nonlocal verdict
        reasons.append(reason)
        if ORDER.index(level) > ORDER.index(verdict):
            verdict = level

    for rep in reputations:
        if rep.error:
            reasons.append(f"{rep.provider}: {rep.error}")
            continue
        if rep.provider == "virustotal":
            if rep.malicious >= VT_MALICIOUS:
                raise_to("malicious", f"VirusTotal: {rep.malicious} engines flag it as malicious")
            elif rep.malicious + rep.suspicious >= VT_SUSPICIOUS:
                raise_to("suspicious", f"VirusTotal: {rep.malicious} malicious / "
                                       f"{rep.suspicious} suspicious detections")
            else:
                raise_to("clean", "VirusTotal: no detections")
        elif rep.provider == "abuseipdb" and rep.abuse_score is not None:
            if rep.abuse_score >= ABUSE_MALICIOUS:
                raise_to("malicious", f"AbuseIPDB confidence {rep.abuse_score}/100")
            elif rep.abuse_score >= ABUSE_SUSPICIOUS:
                raise_to("suspicious", f"AbuseIPDB confidence {rep.abuse_score}/100")
            else:
                raise_to("clean", f"AbuseIPDB confidence {rep.abuse_score}/100")
    return IndicatorVerdict(indicator, verdict, reasons)


def overall(verdicts: list[IndicatorVerdict]) -> str:
    return max((v.verdict for v in verdicts), key=ORDER.index, default="unknown")


def propose_actions(incident: dict, indicators: list[Indicator],
                    verdicts: list[IndicatorVerdict]) -> list[ProposedAction]:
    actions = [ProposedAction(
        "add_incident_comment", "incident",
        "Record the enrichment results on the incident for the analyst.",
        requires_approval=False)]
    for v in verdicts:
        if v.verdict != "malicious":
            continue
        if v.indicator.kind == "ip":
            actions.append(ProposedAction(
                "block_ip_indicator", v.indicator.value,
                "; ".join(v.reasons), requires_approval=True))
        elif v.indicator.kind in ("filehash", "url"):
            actions.append(ProposedAction(
                f"block_{v.indicator.kind}_indicator", v.indicator.value,
                "; ".join(v.reasons), requires_approval=True))

    accounts = [i.value for i in indicators if i.kind == "account"]
    title = str(incident.get("properties", {}).get("title", "")).lower()
    identity_alert = any(word in title for word in ("mfa", "password spray", "sign-in", "token"))
    if accounts and (identity_alert or overall(verdicts) == "malicious"):
        for account in accounts:
            actions.append(ProposedAction(
                "revoke_sessions_and_reset_password", account,
                "Identity-related incident or malicious indicator linked to this account.",
                requires_approval=True))
    return actions
