"""Post the enrichment report as a comment on a Microsoft Sentinel incident.

Uses the Azure Resource Manager REST API (Microsoft.SecurityInsights, incident
comments). A comment is the only write this playbook performs, because it
changes nothing in the environment. Authentication is a bearer token, for
example from ``az account get-access-token --resource https://management.azure.com``
or a managed identity when the playbook runs as an Azure Function.
"""

from __future__ import annotations

import json
import os
import urllib.request
import uuid

API_VERSION = "2024-03-01"


def comment_url(subscription: str, resource_group: str, workspace: str, incident_id: str) -> str:
    return (
        "https://management.azure.com"
        f"/subscriptions/{subscription}/resourceGroups/{resource_group}"
        f"/providers/Microsoft.OperationalInsights/workspaces/{workspace}"
        f"/providers/Microsoft.SecurityInsights/incidents/{incident_id}"
        f"/comments/{uuid.uuid4()}?api-version={API_VERSION}"
    )


def post_comment(incident_id: str, message: str) -> int:
    url = comment_url(os.environ["AZURE_SUBSCRIPTION_ID"], os.environ["AZURE_RESOURCE_GROUP"],
                      os.environ["SENTINEL_WORKSPACE"], incident_id)
    body = json.dumps({"properties": {"message": message[:30000]}}).encode("utf-8")
    request = urllib.request.Request(url, data=body, method="PUT", headers={
        "Authorization": f"Bearer {os.environ['AZURE_ACCESS_TOKEN']}",
        "Content-Type": "application/json",
    })
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.status
