import json
from datetime import datetime


def calculate_risk_score(alert, threat_info=None):

    score = 0

    # -----------------------------------------
    # 1. Base severity score
    # -----------------------------------------

    if alert["severity"] == "LOW":
        score += 20

    elif alert["severity"] == "MEDIUM":
        score += 40

    elif alert["severity"] == "HIGH":
        score += 70


    # -----------------------------------------
    # 2. Attack type
    # -----------------------------------------

    attack_type = alert["alert_type"]

    if attack_type == "Brute Force Attack":
        score += 10

    elif attack_type == "Login After Multiple Failures":
        score += 15

    elif attack_type == "Account Login Attack":
        score += 15

    elif attack_type == "Suspicious IP Activity":
        score += 5


    # -----------------------------------------
    # 3. Number of attempts
    # -----------------------------------------

    attempts = alert["attempts"]

    if attempts >= 10:
        score += 20

    elif attempts >= 5:
        score += 10

    elif attempts >= 3:
        score += 5


    # -----------------------------------------
    # 4. Threat Intelligence
    # -----------------------------------------

    if threat_info:

        reputation = threat_info.get(
            "reputation",
            ""
        )

        confidence = threat_info.get(
            "confidence",
            0
        )

        if reputation == "Malicious":
            score += 15

        elif reputation == "Suspicious":
            score += 8

        # High confidence threat intelligence
        if confidence >= 90:
            score += 5


    # Maximum score = 100

    if score > 100:
        score = 100


    return score


def get_risk_level(score):

    if score >= 80:
        return "CRITICAL"

    elif score >= 60:
        return "HIGH"

    elif score >= 30:
        return "MEDIUM"

    else:
        return "LOW"


def load_alerts():

    with open(
        "data/alerts.json",
        "r"
    ) as file:

        return json.load(file)


def load_threat_intelligence():

    try:

        with open(
            "data/threat_intelligence.json",
            "r"
        ) as file:

            return json.load(file)

    except FileNotFoundError:

        return []


def get_threat_info(ip_address, threat_data):

    for threat in threat_data:

        if threat["ip_address"] == ip_address:

            return threat

    return None


def assess_alert(
    alert,
    threat_data
):

    threat_info = get_threat_info(
        alert["source_ip"],
        threat_data
    )

    score = calculate_risk_score(
        alert,
        threat_info
    )

    risk_level = get_risk_level(
        score
    )

    return {

        "alert_id":
            alert["alert_id"],

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
            alert["severity"],

        "risk_score":
            score,

        "risk_level":
            risk_level
    }


def save_risk_assessments(
    assessments
):

    with open(
        "data/risk_assessments.json",
        "w"
    ) as file:

        json.dump(
            assessments,
            file,
            indent=4
        )


if __name__ == "__main__":

    print(
        "=== SentinelX Risk Engine ==="
    )

    alerts = load_alerts()

    threat_data = (
        load_threat_intelligence()
    )

    assessments = []

    for alert in alerts:

        assessment = assess_alert(
            alert,
            threat_data
        )

        assessments.append(
            assessment
        )

    save_risk_assessments(
        assessments
    )

    print(
        f"Risk assessments created: "
        f"{len(assessments)}"
    )

    print("--------------------------------")

    for assessment in assessments:

        print(
            f"Alert ID: "
            f"{assessment['alert_id']} | "
            f"{assessment['alert_type']} | "
            f"IP: "
            f"{assessment['source_ip']} | "
            f"Risk: "
            f"{assessment['risk_score']}/100 | "
            f"{assessment['risk_level']}"
        )

    print("--------------------------------")

    print(
        "Risk assessment completed successfully."
    )