"""Extract indicators from a Microsoft Sentinel incident.

The input mirrors what the Sentinel REST API returns for an incident
(``properties``) plus its related entities (``POST .../incidents/{id}/entities``),
where each entity has a ``kind`` and a ``properties`` object.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass


@dataclass(frozen=True)
class Indicator:
    kind: str   # ip | url | filehash | account | host
    value: str

    @property
    def is_public_ip(self) -> bool:
        if self.kind != "ip":
            return False
        try:
            return ipaddress.ip_address(self.value).is_global
        except ValueError:
            return False


def _account(props: dict) -> str | None:
    name, suffix = props.get("accountName"), props.get("upnSuffix")
    if name and suffix:
        return f"{name}@{suffix}"
    return props.get("aadUserId") or name


def extract_indicators(incident: dict) -> list[Indicator]:
    """Return unique, normalised indicators in the order they appear."""
    found: list[Indicator] = []
    for entity in incident.get("entities", []) or []:
        kind = str(entity.get("kind", "")).lower()
        props = entity.get("properties", {}) or {}
        value = None
        if kind == "ip":
            value = props.get("address")
        elif kind == "url":
            value = props.get("url")
        elif kind == "filehash":
            value = str(props.get("hashValue", "")).lower() or None
        elif kind == "account":
            value = _account(props)
        elif kind == "host":
            value = props.get("hostName")
        if value:
            indicator = Indicator(kind, str(value).strip())
            if indicator not in found:
                found.append(indicator)
    return found
