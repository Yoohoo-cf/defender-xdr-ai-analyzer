import os
import json
import requests

# ===========================================
# 1. LOAD ENVIRONMENT VARIABLES
# ===========================================

TENANT_ID = os.environ["TENANT_ID"]
CLIENT_ID = os.environ["CLIENT_ID"]
CLIENT_SECRET = os.environ["CLIENT_SECRET"]

# ============================================================
# 2. CONFIGURATION
# ============================================================

TOKEN_URL = (f"https://login.microsoftonline.com/"
             f"{TENANT_ID}/oauth2/v2.0/token"
)

DEFENDER_INCIDENTS_URL = (
    "https://api.security.microsoft.com/api/incidents?$top=5"
)

OLLAMA_URL = "http://localhost:11434/api/generate"

OLLAMA_MODEL = "llama3.2:1b"

# ============================================================
# 3. GET ACCESS TOKEN FROM MICROSOFT ENTRA ID
# ============================================================

def get_access_token():

    token_data = {
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "scope": "https://api.security.microsoft.com/.default",
        "grant_type": "client_credentials"
    }

    response = requests.post(
        TOKEN_URL,
        data=token_data,
        timeout=30
    )

    response.raise_for_status()

    token = response.json()["access_token"]

    return token

# ============================================================
# 4. GET DEFENDER XDR INCIDENTS
# ============================================================

def get_incidents(access_token):

    headers = {
        "Authorization": f"Bearer {access_token}",
        "Content-Type": "application/json"
    }

    response = requests.get(
        DEFENDER_INCIDENTS_URL,
        headers=headers,
        timeout=30
    )

    response.raise_for_status()

    data = response.json()

    incidents = data.get("value", [])

    return incidents

# ============================================================
# 5. PREPARE INCIDENT FOR AI
# ===========================================================
def normalize_device(device):
    """
    Extract security-relevant information from a Defender XDR device.
    """

    return {
        "deviceName": device.get("deviceDnsName"),
        "osPlatform": device.get("osPlatform"),
        "osVersion": device.get("version"),
        "healthStatus": device.get("healthStatus"),
        "riskScore": device.get("riskScore"),
        "firstSeen": device.get("firstSeen"),
        "onboardingStatus": device.get("onboardingStatus"),
        "tags": device.get("tags", []),
        "loggedOnUsers": device.get("loggedOnUsers", [])
    }


def normalize_entity(entity):
    """
    Extract security-relevant information from a Defender XDR entity.
    """

    entity_type = entity.get("entityType")

    normalized = {
        "entityType": entity_type,
        "verdict": entity.get("verdict"),
        "remediationStatus": entity.get("remediationStatus")
    }

    if entity_type == "User":
        normalized["accountName"] = entity.get("accountName")
        normalized["domainName"] = entity.get("domainName")

    elif entity_type == "Ip":
        normalized["ipAddress"] = entity.get("ipAddress")

    return normalized

def prepare_incident(incident):
    normalized_alerts = []

    for alert in incident.get("alerts", []):

        normalized_alert = {
            "alertId": alert.get("alertId"),
            "title": alert.get("title"),
            "description": alert.get("description"),
            "severity": alert.get("severity"),
            "status": alert.get("status"),
            "category": alert.get("category"),
            "serviceSource": alert.get("serviceSource"),
            "detectionSource": alert.get("detectionSource"),
            "firstActivity": alert.get("firstActivity"),
            "lastActivity": alert.get("lastActivity"),
            "classification": alert.get("classification"),
            "determination": alert.get("determination"),
            "threatFamilyName": alert.get("threatFamilyName"),
            "mitreTechniques": alert.get("mitreTechniques", []),
            "devices": [
                normalize_device(device)
                for device in alert.get("devices", [])
            ],
            "entities": [
                normalize_entity(entity)
                for entity in alert.get("entities", [])
            ]
        }

        normalized_alerts.append(normalized_alert)

    incident_for_ai = {
        "incidentId": incident.get("incidentId"),
        "incidentName": incident.get("incidentName"),
        "severity": incident.get("severity"),
        "status": incident.get("status"),
        "classification": incident.get("classification"),
        "determination": incident.get("determination"),
        "createdTime": incident.get("createdTime"),
        "lastUpdateTime": incident.get("lastUpdateTime"),
        "tags": incident.get("tags", []),
        "alerts": normalized_alerts
    }

    return incident_for_ai

# ================================================================
# 6. BUILD PROMPT FOR LLAMA
# ==========================================================

def build_prompt(incident):

    incident_json = json.dumps(
        incident,
        indent=2
    )

    prompt = f"""
You are a SOC security analyst.

Analyze the following Microsoft Defender XDR incident.

Incident data:

{incident_json}

Your task is to provide a structured security investigation.

Return the following sections:

1. Incident Summary
   - Explain what happened in simple terms.

2. Severity Assessment
   - State whether the severity appears appropriate.
   - Explain why.

3. Possible Threat
   - Identify the possible attack technique or threat scenario.
   - Do not invent facts that are not present in the incident.

4. Important Evidence
   - Identify the most important alerts, devices, users, IP addresses,
     processes, or other evidence contained in the incident.

5. Investigation Steps
   - Give a clear step-by-step investigation plan for a SOC analyst.

6. Containment Recommendations
   - Suggest appropriate containment actions.
   - Clearly separate immediate actions from optional actions.

7. Escalation Decision
   - State whether this incident should be escalated immediately.
   - Explain the reasoning.

Important rules:

- Only use evidence provided in the incident.
- If information is missing, explicitly say that the information is missing.
- Do not invent IP addresses, usernames, processes, devices, or malware names.
- Treat this as a real Microsoft Defender XDR investigation.
"""

    return prompt


# ============================================================
# 7. SEND INCIDENT TO OLLAMA
# ============================================================

def analyze_with_ollama(prompt):

    payload = {
        "model": OLLAMA_MODEL,
        "prompt": prompt,
        "stream": False
    }

    response = requests.post(
        OLLAMA_URL,
        json=payload,
        timeout=600
    )

    response.raise_for_status()

    result = response.json()

    return result["response"]

# ============================================================
# 8. MAIN PROGRAM
# ============================================================

def main():

    print("Getting Microsoft Defender XDR access token...")

    access_token = get_access_token()

    print("Access token obtained successfully.")


    print("\nGetting Defender XDR incidents...")

    incidents = get_incidents(access_token)

    print(f"Incidents found: {len(incidents)}")


    if not incidents:
        print("No Defender XDR incidents were returned.")
        return


    # For now, analyze only the first incident
    incident = incidents[0]

    with open("incident_sample.json", "w") as f:
        json.dump(incident, f, indent=2)


    print("Saved incident to incident_sample.json")



    print("\nSelected incident:")

    print(
        f"ID: {incident.get('incidentId')}"
    )

    print(
        f"Name: {incident.get('incidentName')}"
    )

    print(
        f"Severity: {incident.get('severity')}"
    )


    incident_for_ai = prepare_incident(incident)

    prompt = build_prompt(incident_for_ai)


    print("\nSending incident to local Ollama model...")

    analysis = analyze_with_ollama(prompt)


    print("\n")
    print("=" * 70)
    print("AI SECURITY ANALYSIS")
    print("=" * 70)
    print()

    print(analysis)

    print()
    print("=" * 70)


# ============================================================
# 9. RUN PROGRAM
# ============================================================

if __name__ == "__main__":
    main()
