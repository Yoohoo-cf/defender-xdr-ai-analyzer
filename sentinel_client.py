import os
import requests


def get_sentinel_access_token():
    """Get an access token for Azure Monitor / Log Analytics API using client credentials flow."""

    TENANT_ID = os.environ["TENANT_ID"]
    CLIENT_ID = os.environ["CLIENT_ID"]
    CLIENT_SECRET = os.environ["CLIENT_SECRET"]

    token_url = (
        f"https://login.microsoftonline.com/"
        f"{TENANT_ID}/oauth2/v2.0/token"
    )

    data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": "https://api.loganalytics.io/.default",
        "grant_type": "client_credentials"
    }

    response = requests.post(
        token_url,
        data=data,
        timeout=30
    )
    response.raise_for_status()

    token_data = response.json().get("access_token")
    if not token_data:
        raise ValueError("Token response did not include an access_token.")

    return token_data


def query_sentinel(access_token, query, timespan="P7D"):
    """Execute a Kusto query against the Azure Sentinel / Log Analytics workspace."""

    WORKSPACE_ID = os.environ["WORKSPACE_ID"]

    url = (
        "https://api.loganalytics.azure.com/v1/workspaces/"
        f"{WORKSPACE_ID}/query"
    )

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    body = {
        "query": query,
        "timespan": timespan
    }


    # print("\nSending query to Log Analytics workspace...")
    # print("Query:", query)
    # print("Timespan:", body["timespan"])

    response = requests.post(
        url,
        headers=headers,
        json=body,
        timeout=60
    )
    response.raise_for_status()

    return response.json()

def extract_rows(result):

    """Extract rows from the query result."""
    tables = result.get("tables", [])
    if not tables:
        return []

    rows = []
    for table in tables:
        columns = [col["name"] for col in table.get("columns", [])]
        for row in table.get("rows", []):
            row_dict = dict(zip(columns, row))
            rows.append(row_dict)

    return rows

    