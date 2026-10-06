import json


def load_logs():
    with open("data/security_logs.json", "r") as file:
        logs = json.load(file)

    return logs


if __name__ == "__main__":
    logs = load_logs()

    print(f"Total security events: {len(logs)}")

    for log in logs:
        print(
            f"{log['timestamp']} | "
            f"{log['username']} | "
            f"{log['source_ip']} | "
            f"{log['event_type']}"
        )