import os
import requests

tenant_id = os.environ["TENANT_ID"]
client_id = os.environ["CLIENT_ID"]
client_secret = os.environ["CLIENT_SECRET"]

# Step 1: Get OAuth token
token_url = f"https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"

token_data = {
    "client_id": client_id,
    "client_secret": client_secret,
    "scope": "https://api.security.microsoft.com/.default",
    "grant_type": "client_credentials"
}

token_response = requests.post(
    token_url,
    data=token_data,
    timeout=30
)

token_response.raise_for_status()

access_token = token_response.json()["access_token"]

print("Successfully obtained Defender XDR access token.")

# Step 2: Call Defender XDR incidents API
headers = {
    "Authorization": f"Bearer {access_token}"
}

incidents_url = "https://api.security.microsoft.com/api/incidents?$top=5"

response = requests.get(
    incidents_url,
    headers=headers,
    timeout=30
)

response.raise_for_status()

data = response.json()

print(f"Incidents returned: {len(data.get('value', []))}")

for incident in data.get("value", []):
    print("-" * 60)
    print("Incident ID:", incident.get("incidentId"))
    print("Name:", incident.get("incidentName"))
    print("Severity:", incident.get("severity"))
    print("Status:", incident.get("status"))
    print("Created:", incident.get("createdTime"))
