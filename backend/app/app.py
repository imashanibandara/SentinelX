from flask import Flask, jsonify, request
import json

from services.incident_manager import (
    load_incidents,
    update_incident
)

from services.response_manager import (
    load_blocked_ips,
    block_ip,
    unblock_ip
)

from flask_cors import CORS


app = Flask(__name__)
CORS(app)
@app.route("/")
def home():
    return jsonify({
        "message": "SentinelX Security Monitoring API",
        "status": "online"
    })

@app.route("/api/alerts")
def get_alerts():

    try:

        with open("data/alerts.json", "r") as file:
            alerts = json.load(file)

        return jsonify(alerts)

    except FileNotFoundError:

        return jsonify({
            "error": "Alerts file not found"
        }), 404


# =========================================
# Security Activity API
# =========================================

@app.route("/api/security-logs")
def get_security_logs():

    try:

        with open(
            "data/security_logs.json",
            "r"
        ) as file:

            logs = json.load(file)

        return jsonify(logs)

    except FileNotFoundError:

        return jsonify({
            "error": "Security logs not found"
        }), 404

@app.route("/api/analytics")
def get_analytics():

    try:

        with open("data/security_logs.json", "r") as file:
            logs = json.load(file)

        with open("data/alerts.json", "r") as file:
            alerts = json.load(file)

        with open("data/risk_assessments.json", "r") as file:
            assessments = json.load(file)


        # =====================================
        # Login Statistics
        # =====================================

        login_failed = 0
        login_success = 0

        for log in logs:

            if log["event_type"] == "login_failed":
                login_failed += 1

            elif log["event_type"] == "login_success":
                login_success += 1


        # =====================================
        # Attack Type Distribution
        # =====================================

        attack_types = {}

        for alert in alerts:

            attack_type = alert["alert_type"]

            if attack_type not in attack_types:
                attack_types[attack_type] = 0

            attack_types[attack_type] += 1


        # =====================================
        # Risk Distribution
        # =====================================

        risk_distribution = {
            "CRITICAL": 0,
            "HIGH": 0,
            "MEDIUM": 0,
            "LOW": 0
        }

        for assessment in assessments:

            level = assessment["risk_level"]

            if level in risk_distribution:
                risk_distribution[level] += 1


        # =====================================
        # Top Suspicious IPs
        # =====================================

        ip_activity = {}

        for log in logs:

            ip = log["source_ip"]

            if ip not in ip_activity:
                ip_activity[ip] = 0

            ip_activity[ip] += 1


        top_ips = sorted(
            ip_activity.items(),
            key=lambda item: item[1],
            reverse=True
        )[:5]


        top_suspicious_ips = []

        for ip, count in top_ips:

            top_suspicious_ips.append({
                "ip": ip,
                "events": count
            })


        return jsonify({

            "login_statistics": {
                "failed": login_failed,
                "success": login_success
            },

            "attack_types": attack_types,

            "risk_distribution":
                risk_distribution,

            "top_suspicious_ips":
                top_suspicious_ips

        })


    except FileNotFoundError:

        return jsonify({
            "error": "Analytics data files not found"
        }), 404

@app.route("/api/risk-assessments")
def get_risk_assessments():

    try:

        with open("data/risk_assessments.json", "r") as file:
            assessments = json.load(file)

        return jsonify(assessments)

    except FileNotFoundError:

        return jsonify({
            "error": "Risk assessments file not found"
        }), 404



@app.route("/api/summary")
def get_summary():

    try:

        with open("data/alerts.json", "r") as file:
            alerts = json.load(file)

        with open("data/risk_assessments.json", "r") as file:
            assessments = json.load(file)

        critical_count = 0
        high_count = 0
        medium_count = 0
        low_count = 0

        for assessment in assessments:

            risk_level = assessment["risk_level"]

            if risk_level == "CRITICAL":
                critical_count += 1

            elif risk_level == "HIGH":
                high_count += 1

            elif risk_level == "MEDIUM":
                medium_count += 1

            elif risk_level == "LOW":
                low_count += 1

        return jsonify({
            "total_alerts": len(alerts),
            "critical": critical_count,
            "high": high_count,
            "medium": medium_count,
            "low": low_count
        })

    except FileNotFoundError:

        return jsonify({
            "error": "Security data files not found"
        }), 404

@app.route("/api/threat-intelligence")
def get_threat_intelligence():

    try:

        with open(
            "data/threat_intelligence.json",
            "r"
        ) as file:

            threat_data = json.load(file)

        return jsonify(threat_data)

    except FileNotFoundError:

        return jsonify({
            "error":
            "Threat intelligence data not found"
        }), 404


# =========================================
# Incident Management API
# =========================================

@app.route("/api/incidents")
def get_incidents():

    try:

        incidents = load_incidents()

        return jsonify(incidents)

    except FileNotFoundError:

        return jsonify({
            "error":
            "Incident data not found"
        }), 404


@app.route("/api/incidents/<int:alert_id>", methods=["PUT"])
def update_incident_status(alert_id):

    data = request.get_json()

    if not data:

        return jsonify({
            "error": "Request data is required"
        }), 400

    status = data.get("status")
    notes = data.get("notes", "")

    allowed_statuses = [
        "Open",
        "Investigating",
        "Resolved"
    ]

    if status not in allowed_statuses:

        return jsonify({
            "error":
            "Invalid incident status"
        }), 400

    incident = update_incident(
        alert_id,
        status,
        notes
    )

    if incident is None:

        return jsonify({
            "error":
            "Incident not found"
        }), 404

    return jsonify(incident)


@app.route("/api/blocked-ips")
def get_blocked_ips():

    try:

        blocked_ips = load_blocked_ips()

        return jsonify(blocked_ips)

    except Exception as error:

        return jsonify({
            "error": str(error)
        }), 500


@app.route(
    "/api/response/block",
    methods=["POST"]
)
def block_ip_address():

    data = request.get_json()

    if not data:

        return jsonify({
            "error": "Request data is required"
        }), 400


    ip_address = data.get(
        "ip_address"
    )


    if not ip_address:

        return jsonify({
            "error": "IP address is required"
        }), 400


    result = block_ip(
        ip_address
    )


    if not result["success"]:

        return jsonify(result), 409


    return jsonify(result), 200


@app.route(
    "/api/response/unblock",
    methods=["POST"]
)
def unblock_ip_address():

    data = request.get_json()

    if not data:

        return jsonify({
            "error": "Request data is required"
        }), 400


    ip_address = data.get(
        "ip_address"
    )


    if not ip_address:

        return jsonify({
            "error": "IP address is required"
        }), 400


    result = unblock_ip(
        ip_address
    )


    if not result["success"]:

        return jsonify(result), 404


    return jsonify(result), 200


if __name__ == "__main__":
    app.run(debug=True)