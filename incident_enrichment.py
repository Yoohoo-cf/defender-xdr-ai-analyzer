import json
import requests

from sentinel_client import get_sentinel_access_token, query_sentinel, extract_rows


def extract_device_names(incident):
    """Extracts device names from the given incident."""
    device_names = set()

    for alert in incident.get("alerts", []):
        for device in alert.get("devices", []):
            name = device.get("deviceName")
            if name:
                device_names.add(name)

    return sorted(device_names)


def query_device_activity(access_token, device_name):
    """Query Azure Sentinel for activity related to the given device name."""

    if not isinstance(device_name, str) or not device_name.strip():
        raise ValueError("Device name is required.")

    safe_device_name = json.dumps(
        device_name
    )  # Safely escape the device name for Kusto query

    query = f"""
    let targetDevice = {safe_device_name};
    DeviceEvents
    | where DeviceName =~ targetDevice
    | project Timestamp, DeviceName, ActionType, InitiatingProcessFileName
    | order by Timestamp desc
    | take 20
    """
    result = query_sentinel(access_token, query, timespan="P7D")

    return extract_rows(result)


def enrich_incident_with_device_activity(incident):
    """Enriches an XDR incident with Sentinel device activity."""
    device_names = extract_device_names(incident)

    enriched_incident = incident.copy()

    enriched_incident["enriched_device_activity"] = {}
    enriched_incident["enrichment_errors"] = {}

    if not device_names:
        return enriched_incident  # No device names to enrich

    access_token = get_sentinel_access_token()

    for device_name in device_names:
        try:
            activity_data = query_device_activity(access_token, device_name)
            enriched_incident["enriched_device_activity"][device_name] = activity_data
        except Exception as e:

            enriched_incident["enriched_device_activity"][device_name] = []
            enriched_incident["enrichment_errors"][device_name] = str(e)

    return enriched_incident
