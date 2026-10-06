from log_parser import load_logs


def detect_brute_force(logs):
    failed_attempts = {}

    for log in logs:

        if log["event_type"] == "login_failed":

            ip = log["source_ip"]

            if ip not in failed_attempts:
                failed_attempts[ip] = 0

            failed_attempts[ip] += 1

    alerts = []

    for ip, attempts in failed_attempts.items():

        if attempts >= 3:

            alerts.append({
                "alert_type": "Brute Force Attack",
                "source_ip": ip,
                "attempts": attempts,
                "severity": "HIGH"
            })

    return alerts


def detect_suspicious_ip(logs):

    suspicious_ips = {}

    for log in logs:

        ip = log["source_ip"]

        # Ignore private/local network addresses
        if (
            not ip.startswith("192.168.") and
            not ip.startswith("10.") and
            not ip.startswith("172.16.")
        ):

            if ip not in suspicious_ips:
                suspicious_ips[ip] = 0

            suspicious_ips[ip] += 1

    alerts = []

    for ip, attempts in suspicious_ips.items():

        alerts.append({
            "alert_type": "Suspicious IP Activity",
            "source_ip": ip,
            "attempts": attempts,
            "severity": "MEDIUM"
        })

    return alerts


# Detect successful login after multiple failed attempts
def detect_login_after_failures(logs):

    alerts = []

    failed_attempts = {}

    for log in logs:

        ip = log["source_ip"]

        if log["event_type"] == "login_failed":

            if ip not in failed_attempts:
                failed_attempts[ip] = 0

            failed_attempts[ip] += 1

        elif log["event_type"] == "login_success":

            attempts = failed_attempts.get(ip, 0)

            if attempts >= 3:

                alerts.append({
                    "alert_type": "Login After Multiple Failures",
                    "source_ip": ip,
                    "attempts": attempts,
                    "severity": "HIGH"
                })

    return alerts


# Detect repeated login failures from the same account
def detect_account_attack(logs):

    failed_accounts = {}

    for log in logs:

        if log["event_type"] == "login_failed":

            username = log["username"]

            if username not in failed_accounts:
                failed_accounts[username] = 0

            failed_accounts[username] += 1

    alerts = []

    for username, attempts in failed_accounts.items():

        if attempts >= 3:

            alerts.append({
                "alert_type": "Account Login Attack",
                "source_ip": "Multiple",
                "attempts": attempts,
                "severity": "HIGH"
            })

    return alerts


def detect_threats(logs):

    alerts = []

    alerts.extend(
        detect_brute_force(logs)
    )

    alerts.extend(
        detect_suspicious_ip(logs)
    )

    alerts.extend(
        detect_login_after_failures(logs)
    )

    alerts.extend(
        detect_account_attack(logs)
    )

    return alerts


if __name__ == "__main__":

    logs = load_logs()

    alerts = detect_threats(logs)

    print("=== SentinelX Detection Engine ===")

    if not alerts:

        print("No suspicious activity detected.")

    else:

        print(
            f"Alerts detected: {len(alerts)}"
        )

        for alert in alerts:

            print(
                f"🚨 {alert['alert_type']} | "
                f"IP: {alert['source_ip']} | "
                f"Attempts: {alert['attempts']} | "
                f"Severity: {alert['severity']}"
            )