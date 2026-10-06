import os
import requests

# Configuration Environment

TENANT_ID = os.environ["TENANT_ID"]
CLIENT_ID = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]
WORKSPACE_ID = os.environ["WORKSPACE_ID"]


# ==============================================
# Step 1: Get Azure Monitor access token
# ==============================================

def get_access_token():
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

    if not response.ok:
        print("\nToken request failed:")
        print("Status:", response.status_code)
        print(response.text)
        response.raise_for_status()

    token_data = response.json()
    access_token = token_data.get("access_token")
    if not access_token:
        raise ValueError("Token response did not include an access_token.")

    return access_token


# ========================================
# Step 2: Query Log Analytics / Sentinel
# =======================================

def query_log_analytics(access_token):
    url = (
        "https://api.loganalytics.azure.com/v1/workspaces/"
        f"{WORKSPACE_ID}/query"
    )

    query = """
    DeviceEvents
    | project
    Timestamp,
    DeviceName,
    ActionType,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
    | order by Timestamp desc
    | take 10
    """

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    body = {
        "query": query,
        "timespan": "P7D"
    }

    print("\nSending query to Log Analytics workspace...")
    print("Query:", query)
    print("Timespan:", body["timespan"])

    response = requests.post(
        url,
        headers=headers,
        json=body,
        timeout=60
    )

    if not response.ok:
        print("\nLog Analytics query failed:")
        print("Status:", response.status_code)
        print(response.text)
        response.raise_for_status()

    return response.json()


# =========================================
# Step 3: Display returned data
# ===========================================

def display_results(result):
    tables = result.get("tables", [])

    print(f"\nTables returned: {len(tables)}")

    if not tables:
        print("No tables were returned.")
        return

    for table in tables:
        print("\n======================")
        print(f"Table: {table.get('name')}")
        print("=========================")

        columns = [column.get("name") for column in table.get("columns", [])]

        print("\nColumns:")
        print(columns)

        rows = table.get("rows", [])

        print(f"\nRows returned: {len(rows)}")

        for row in rows:
            print(row)


# ==========================================
# Main program
# ==========================================
def main():
    print("Starting Sentinel API test...")

    print("\nGetting Azure Monitor access token...")
    access_token = get_access_token()
    print("Access token obtained successfully.")

    print("\nQuerying Log Analytics workspace...")
    result = query_log_analytics(access_token)
    print("Query successful.")

    display_results(result)

    print("\nSentinel API test completed.")


if __name__ == "__main__":
    main()


