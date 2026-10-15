
import json
from pathlib import Path

from incident_enrichment import (
    extract_device_names,
    enrich_incident_with_device_activity,
)


def main():
    incident_file = Path("normalized_incident.json")

    if not incident_file.exists():
        print(f"Incident file {incident_file} does not exist.")
        return

    with incident_file.open("r", encoding="utf-8") as f:
        incident_data = json.load(f)

    # Extract device names
    device_names = extract_device_names(incident_data)
    print(f"Devices found: {len(device_names)}")

    if not device_names:
        print("No device names found in the incident data.")
        return

    print("Enriching incident data with device activity...")

    # Enrich incident with Sentinel activity
    enriched_incident = enrich_incident_with_device_activity(
        incident_data
    )

    device_activity = enriched_incident.get(
        "enriched_device_activity", {}
    )

    enrichment_errors = enriched_incident.get(
        "enrichment_errors", {}
    )

    for device_name, events in device_activity.items():
        print(f"Device: {device_name}")
        print(f"Matching Sentinel events: {len(events)}")

    print(f"Devices with query errors: {len(enrichment_errors)}")
    print("Enrichment test completed.")


if __name__ == "__main__":
    main()
