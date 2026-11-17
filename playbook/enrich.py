"""Enrich a Microsoft Sentinel incident and propose a response.

Pipeline:  extract indicators -> threat-intel lookups -> deterministic verdict
           -> proposed actions (human approval) -> LLM summary -> report

    # offline demo with recorded API answers, no keys needed
    python -m playbook.enrich samples/incident_mfa_fatigue.json --offline --no-llm

    # live lookups (VT_API_KEY, ABUSEIPDB_API_KEY) and a Claude summary (ANTHROPIC_API_KEY)
    python -m playbook.enrich incident.json --json-out result.json

    # also post the report as an incident comment (AZURE_* variables, see sentinel_api.py)
    python -m playbook.enrich incident.json --post-comment
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

from . import llm, sentinel_api
from .entities import extract_indicators
from .providers import AbuseIPDB, FixtureProvider, VirusTotal
from .verdict import overall, propose_actions, score_indicator

FIXTURES = Path(__file__).resolve().parent.parent / "samples" / "fixtures"


def build_providers(offline: bool) -> list:
    if offline:
        return [FixtureProvider("virustotal", FIXTURES / "virustotal.json", VirusTotal),
                FixtureProvider("abuseipdb", FIXTURES / "abuseipdb.json", AbuseIPDB)]
    providers = []
    if os.environ.get("VT_API_KEY"):
        providers.append(VirusTotal(os.environ["VT_API_KEY"]))
    if os.environ.get("ABUSEIPDB_API_KEY"):
        providers.append(AbuseIPDB(os.environ["ABUSEIPDB_API_KEY"]))
    return providers


def run(incident: dict, providers: list, use_llm: bool = True, llm_client=None) -> dict:
    props = incident.get("properties", {})
    indicators = extract_indicators(incident)
    verdicts = []
    for indicator in indicators:
        supported = [p for p in providers if p.supports(indicator)]
        verdict = score_indicator(indicator, [p.lookup(indicator) for p in supported])
        if not supported:
            internal_ip = indicator.kind == "ip" and not indicator.is_public_ip
            verdict.reasons.append("internal or non-routable IP, not looked up" if internal_ip
                                   else "no threat-intel provider for this type")
        verdicts.append(verdict)
    actions = propose_actions(incident, indicators, verdicts)

    context = {
        "incident": {
            "number": props.get("incidentNumber"),
            "title": props.get("title"),
            "severity": props.get("severity"),
            "description": props.get("description"),
            "alert_count": props.get("additionalData", {}).get("alertsCount"),
        },
        "overall_verdict": overall(verdicts),
        "indicator_verdicts": [asdict(v) for v in verdicts],
        "proposed_actions": [asdict(a) for a in actions],
    }
    summary = (llm.summarise(context, client=llm_client) if use_llm
               else llm.fallback_summary(context, "LLM disabled (--no-llm)"))
    context["summary"] = summary.to_dict()
    return context


def to_markdown(result: dict) -> str:
    inc, summary = result["incident"], result["summary"]
    lines = [
        f"### Automated enrichment - incident {inc.get('number')}: {inc.get('title')}",
        "",
        f"**Overall verdict:** `{result['overall_verdict']}`  ",
        f"**Suggested classification:** {summary['classification_suggestion']} "
        f"(confidence: {summary['confidence']}, source: {summary['generated_by']})",
        "",
        summary["summary"],
        "",
        "**Indicators**",
        "",
        "| Type | Value | Verdict | Evidence |",
        "| --- | --- | --- | --- |",
    ]
    for v in result["indicator_verdicts"]:
        evidence = "<br>".join(v["reasons"]) or "no provider for this type"
        lines.append(f"| {v['indicator']['kind']} | `{v['indicator']['value']}` | "
                     f"{v['verdict']} | {evidence} |")
    lines += ["", "**Key findings**", ""] + [f"- {x}" for x in summary["key_findings"]]
    lines += ["", "**Proposed actions** (nothing below has been executed)", ""]
    for a in result["proposed_actions"]:
        gate = "REQUIRES ANALYST APPROVAL" if a["requires_approval"] else "automatic"
        lines.append(f"- [ ] `{a['action']}` on `{a['target']}` - {gate}. {a['reason']}")
    lines += ["", "**Next steps**", ""] + [f"- {x}" for x in summary["recommended_next_steps"]]
    if summary.get("note"):
        lines += ["", f"_Note: {summary['note']}_"]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Enrich a Microsoft Sentinel incident.")
    parser.add_argument("incident", type=Path, help="incident JSON (properties + entities)")
    parser.add_argument("--offline", action="store_true",
                        help="use recorded answers from samples/fixtures instead of live APIs")
    parser.add_argument("--no-llm", action="store_true", help="skip the Claude summary")
    parser.add_argument("--json-out", type=Path, help="also write the full result as JSON")
    parser.add_argument("--post-comment", action="store_true",
                        help="post the report as a comment on the Sentinel incident")
    args = parser.parse_args(argv)

    incident = json.loads(args.incident.read_text(encoding="utf-8"))
    providers = build_providers(args.offline)
    if not providers:
        print("warning: no threat-intel provider configured (set VT_API_KEY / "
              "ABUSEIPDB_API_KEY or use --offline)", file=sys.stderr)
    result = run(incident, providers, use_llm=not args.no_llm)
    report = to_markdown(result)
    print(report)
    if args.json_out:
        args.json_out.write_text(json.dumps(result, indent=2), encoding="utf-8")
    if args.post_comment:
        incident_id = incident.get("name") or incident.get("properties", {}).get("incidentNumber")
        status = sentinel_api.post_comment(str(incident_id), report)
        print(f"comment posted (HTTP {status})", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
