import json
from datetime import datetime


# =========================================
# Add New Security Event
# =========================================

def add_security_event(
    username,
    source_ip,
    event_type
):

    event = {
        "timestamp": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),
        "username": username,
        "source_ip": source_ip,
        "event_type": event_type
    }

    with open(
        "data/security_logs.json",
        "r"
    ) as file:

        logs = json.load(file)

    logs.append(event)

    with open(
        "data/security_logs.json",
        "w"
    ) as file:

        json.dump(
            logs,
            file,
            indent=4
        )

    return event


# =========================================
# Brute Force Test Simulation
# =========================================

def simulate_brute_force():

    print("=== SentinelX Event Simulator ===")
    print("Simulating brute-force attack...\n")

    for attempt in range(1, 4):

        event = add_security_event(
            username="test_user",
            source_ip="203.0.113.99",
            event_type="login_failed"
        )

        print(
            f"Attempt {attempt}: "
            f"{event['timestamp']} | "
            f"{event['username']} | "
            f"{event['source_ip']} | "
            f"{event['event_type']}"
        )

    print("\nBrute-force simulation completed.")


# =========================================
# Run Simulator
# =========================================

if __name__ == "__main__":

    simulate_brute_force()