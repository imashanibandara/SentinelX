from log_parser import load_logs
from detection_engine import detect_threats
from alert_manager import save_alerts
from risk_engine import (
    assess_alert,
    save_risk_assessments
)

from threat_intelligence import (
    load_threat_intelligence
)


# =========================================
# Run SentinelX Security Pipeline
# =========================================

def run_pipeline(logs=None):

    print("================================")
    print("      SentinelX Pipeline")
    print("================================")

    # Step 1 - Load security logs
    if logs is None:
        logs = load_logs()

    print(f"Security events loaded: {len(logs)}")

    # Load threat intelligence
    threat_data = load_threat_intelligence()

    # Step 2 - Detect threats
    alerts = detect_threats(logs)

    print(f"Threats detected: {len(alerts)}")

    # Step 3 - Save alerts
    saved_alerts = save_alerts(alerts)

    print(f"Alerts saved: {len(saved_alerts)}")

    # Step 4 - Calculate risk
    assessments = []

    for alert in saved_alerts:

        assessment = assess_alert(
            alert,
            threat_data
        )

        assessments.append(assessment)

    # Step 5 - Save risk assessments
    save_risk_assessments(assessments)

    print(
        f"Risk assessments created: "
        f"{len(assessments)}"
    )

    print("--------------------------------")

    for assessment in assessments:

        print(
            f"{assessment['alert_type']} | "
            f"{assessment['source_ip']} | "
            f"Risk: "
            f"{assessment['risk_score']}/100 | "
            f"{assessment['risk_level']}"
        )

    print("--------------------------------")
    print("Pipeline completed successfully.")


# =========================================
# Run Pipeline
# =========================================

if __name__ == "__main__":

    run_pipeline()