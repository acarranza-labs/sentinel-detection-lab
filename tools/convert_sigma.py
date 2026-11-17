"""Convert the Sigma rules in rules/sigma/ to KQL for Microsoft Sentinel / Defender XDR.

Uses pySigma with the Kusto backend and the Microsoft XDR pipeline, which maps
Sigma ``process_creation`` fields to the ``DeviceProcessEvents`` table. That
table is available in Sentinel through the Microsoft Defender XDR connector.

    python tools/convert_sigma.py           # write rules/kql/*.kql
    python tools/convert_sigma.py --check   # CI: fail if a .kql file is stale
"""

from __future__ import annotations

import argparse
import sys

from sigma.backends.kusto import KustoBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.microsoftxdr import microsoft_xdr_pipeline

from rulelib import KQL_DIR, REPO_ROOT, SIGMA_DIR, kql_path_for

HEADER = (
    "// GENERATED FILE - do not edit by hand.\n"
    "// Source: {source}\n"
    "// Regenerate with: python tools/convert_sigma.py\n"
    "// Rule: {title} ({rule_id})\n"
)


def render(path) -> str:
    collection = SigmaCollection.from_yaml(path.read_text(encoding="utf-8"))
    rule = collection.rules[0]
    backend = KustoBackend(processing_pipeline=microsoft_xdr_pipeline())
    queries = backend.convert(collection)
    if len(queries) != 1:
        raise ValueError(f"{path.name}: expected one query, got {len(queries)}")
    header = HEADER.format(
        source=path.relative_to(REPO_ROOT).as_posix(),
        title=rule.title,
        rule_id=rule.id,
    )
    return header + queries[0].strip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true",
                        help="do not write; exit 1 if any generated file is missing or stale")
    args = parser.parse_args()

    KQL_DIR.mkdir(parents=True, exist_ok=True)
    stale, errors = [], []
    expected = set()
    for path in sorted(SIGMA_DIR.glob("*.yml")):
        target = kql_path_for(path)
        expected.add(target.name)
        try:
            content = render(path)
        except Exception as exc:  # report every broken rule, not just the first
            errors.append(f"{path.name}: {exc}")
            continue
        current = target.read_text(encoding="utf-8") if target.exists() else None
        if current != content:
            stale.append(target.name)
            if not args.check:
                target.write_text(content, encoding="utf-8", newline="\n")

    orphans = sorted(p.name for p in KQL_DIR.glob("*.kql") if p.name not in expected)
    for line in errors:
        print(f"ERROR   {line}")
    for name in orphans:
        print(f"ORPHAN  rules/kql/{name} has no Sigma source")
    if args.check:
        for name in stale:
            print(f"STALE   rules/kql/{name} - run python tools/convert_sigma.py")
        ok = not (errors or stale or orphans)
    else:
        for name in stale:
            print(f"WROTE   rules/kql/{name}")
        ok = not (errors or orphans)
    print(f"{len(expected)} Sigma rule(s) processed; "
          f"{'OK' if ok else 'FAILED'}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
