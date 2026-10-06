import time
import json
import os

from pipeline import run_pipeline
from log_parser import load_logs

# =========================================
# SentinelX Automated Monitoring
# =========================================

STATE_FILE = "data/monitor_state.json"


def load_monitor_state():

    if not os.path.exists(STATE_FILE):

        return {
            "last_processed_event": 0
        }

    with open(
        STATE_FILE,
        "r"
    ) as file:

        return json.load(file)


def save_monitor_state(last_processed_event):

    state = {
        "last_processed_event": last_processed_event
    }

    with open(
        STATE_FILE,
        "w"
    ) as file:

        json.dump(
            state,
            file,
            indent=4
        )


def get_log_count():

    try:

        with open(
            "data/security_logs.json",
            "r"
        ) as file:

            logs = json.load(file)

        return len(logs)

    except Exception:

        return 0


def start_monitoring():

    print("================================")
    print("   SentinelX Security Monitor")
    print("================================")

    print("Monitoring started...")
    print("Checking security events every 30 seconds.")
    print("Press CTRL+C to stop.")
    print("--------------------------------")

    while True:

        try:

            current_event_count = get_log_count()

            state = load_monitor_state()

            last_processed_event = state.get(
                "last_processed_event",
                0
            )

            print(
                f"\n[Monitor] Events: "
                f"{current_event_count}"
            )

            print(
                f"[Monitor] Last processed: "
                f"{last_processed_event}"
            )

            # =========================================
            # Check for new security events
            # =========================================

            if current_event_count > last_processed_event:

                print(
                    "[Monitor] New security events detected."
                )

                all_logs = load_logs()

                new_logs = all_logs[last_processed_event:]

                run_pipeline(new_logs)

                save_monitor_state(
                    current_event_count
                )

                print(
                    "[Monitor] New events processed successfully."
                )

            else:

                print(
                    "[Monitor] No new security events."
                )

            print(
                "[Monitor] Next scan in 30 seconds..."
            )

            time.sleep(30)

        except KeyboardInterrupt:

            print("\n")
            print("Monitoring stopped.")

            break

        except Exception as error:

            print(
                f"[Monitor] Error: {error}"
            )

            print(
                "[Monitor] Retrying in 30 seconds..."
            )

            time.sleep(30)


# =========================================
# Start Monitor
# =========================================

if __name__ == "__main__":

    start_monitoring()