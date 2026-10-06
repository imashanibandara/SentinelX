from detection_engine import detect_threats
from log_parser import load_logs
import json
from datetime import datetime


# =========================================
# Save Detected Alerts
# =========================================

def save_alerts(alerts):

    # Load existing alerts
    try:

        with open(
            "data/alerts.json",
            "r"
        ) as file:

            existing_alerts = json.load(file)

    except (
        FileNotFoundError,
        json.JSONDecodeError
    ):

        existing_alerts = []


    # Start the next alert ID
    if existing_alerts:

        next_alert_id = max(
            alert["alert_id"]
            for alert in existing_alerts
        ) + 1

    else:

        next_alert_id = 1


    new_alerts = []


    for alert in alerts:

        # -----------------------------------------
        # Check if the same alert already exists
        # -----------------------------------------

        duplicate = False

        for existing_alert in existing_alerts:

            same_type = (
                existing_alert["alert_type"]
                == alert["alert_type"]
            )

            same_ip = (
                existing_alert["source_ip"]
                == alert["source_ip"]
            )

            if same_type and same_ip:

                duplicate = True
                break


        # Skip existing alert
        if duplicate:
            continue


        # -----------------------------------------
        # Create new alert
        # -----------------------------------------

        formatted_alert = {

            "alert_id": next_alert_id,

            "timestamp":
                datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                ),

            "alert_type":
                alert["alert_type"],

            "source_ip":
                alert["source_ip"],

            "attempts":
                alert["attempts"],

            "severity":
                alert["severity"]
        }


        new_alerts.append(
            formatted_alert
        )

        next_alert_id += 1


    # -----------------------------------------
    # Save existing + new alerts
    # -----------------------------------------

    all_alerts = (
        existing_alerts
        + new_alerts
    )


    with open(
        "data/alerts.json",
        "w"
    ) as file:

        json.dump(
            all_alerts,
            file,
            indent=4
        )


    return new_alerts


# =========================================
# Main Alert Manager
# =========================================

if __name__ == "__main__":

    logs = load_logs()

    # Detect all supported threats
    alerts = detect_threats(logs)

    # Save alerts
    saved_alerts = save_alerts(alerts)


    print("=== SentinelX Alert Manager ===")


    if not saved_alerts:

        print("No alerts to save.")

    else:

        print(
            f"Saved alerts: {len(saved_alerts)}"
        )


        for alert in saved_alerts:

            print(
                f"Alert ID: {alert['alert_id']} | "
                f"{alert['alert_type']} | "
                f"IP: {alert['source_ip']} | "
                f"Attempts: {alert['attempts']} | "
                f"Severity: {alert['severity']}"
            )