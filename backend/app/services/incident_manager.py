import json
from datetime import datetime


INCIDENT_FILE = "data/incident_status.json"
TIMELINE_FILE = "data/incident_timeline.json"


def load_incidents():

    with open(
        INCIDENT_FILE,
        "r"
    ) as file:

        return json.load(file)


def save_incidents(incidents):

    with open(
        INCIDENT_FILE,
        "w"
    ) as file:

        json.dump(
            incidents,
            file,
            indent=4
        )


def load_timeline():

    try:

        with open(
            TIMELINE_FILE,
            "r"
        ) as file:

            return json.load(file)

    except FileNotFoundError:

        return []


def save_timeline(timeline):

    with open(
        TIMELINE_FILE,
        "w"
    ) as file:

        json.dump(
            timeline,
            file,
            indent=4
        )


def add_timeline_event(
    alert_id,
    action,
    description
):

    timeline = load_timeline()

    event = {

        "alert_id": alert_id,

        "timestamp":
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

        "action": action,

        "description": description

    }

    timeline.append(event)

    save_timeline(timeline)

    return event


def get_incident(alert_id):

    incidents = load_incidents()

    for incident in incidents:

        if incident["alert_id"] == alert_id:

            return incident

    return None


def update_incident(
    alert_id,
    status,
    notes=""
):

    incidents = load_incidents()

    for incident in incidents:

        if incident["alert_id"] == alert_id:

            old_status = incident["status"]

            incident["status"] = status

            incident["notes"] = notes

            incident["updated_at"] = (
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )

            save_incidents(
                incidents
            )

            # Add timeline event
            add_timeline_event(
                alert_id,
                "STATUS_CHANGE",
                f"Incident status changed "
                f"from {old_status} to {status}."
            )

            if notes:

                add_timeline_event(
                    alert_id,
                    "ANALYST_NOTE",
                    notes
                )

            return incident

    return None


if __name__ == "__main__":

    print(
        "=== SentinelX Incident Manager ==="
    )

    incident = update_incident(
        alert_id=1,
        status="Investigating",
        notes="Analyst started investigation."
    )

    if incident:

        print(
            f"Alert ID: "
            f"{incident['alert_id']}"
        )

        print(
            f"Status: "
            f"{incident['status']}"
        )

        print(
            f"Notes: "
            f"{incident['notes']}"
        )

        print(
            f"Updated: "
            f"{incident['updated_at']}"
        )

    else:

        print(
            "Incident not found."
        )