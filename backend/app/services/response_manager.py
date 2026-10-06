import json
from datetime import datetime


BLOCKED_IP_FILE = "data/blocked_ips.json"
AUDIT_LOG_FILE = "data/audit_logs.json"


def load_blocked_ips():

    try:

        with open(
            BLOCKED_IP_FILE,
            "r"
        ) as file:

            return json.load(file)

    except FileNotFoundError:

        return []


def save_blocked_ips(blocked_ips):

    with open(
        BLOCKED_IP_FILE,
        "w"
    ) as file:

        json.dump(
            blocked_ips,
            file,
            indent=4
        )


def load_audit_logs():

    try:

        with open(
            AUDIT_LOG_FILE,
            "r"
        ) as file:

            return json.load(file)

    except FileNotFoundError:

        return []


def save_audit_logs(logs):

    with open(
        AUDIT_LOG_FILE,
        "w"
    ) as file:

        json.dump(
            logs,
            file,
            indent=4
        )


def add_audit_log(
    action,
    ip_address,
    description
):

    logs = load_audit_logs()

    log = {

        "timestamp":
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

        "action": action,

        "ip_address": ip_address,

        "description": description

    }

    logs.append(log)

    save_audit_logs(logs)

    return log


def block_ip(ip_address):

    blocked_ips = load_blocked_ips()

    # Prevent duplicate blocks

    for item in blocked_ips:

        if item["ip_address"] == ip_address:

            return {
                "success": False,
                "message": "IP is already blocked."
            }


    block_record = {

        "ip_address": ip_address,

        "blocked_at":
            datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            ),

        "reason":
            "Automated security response",

        "status": "Blocked"

    }


    blocked_ips.append(
        block_record
    )

    save_blocked_ips(
        blocked_ips
    )


    add_audit_log(

        "IP_BLOCKED",

        ip_address,

        "IP address blocked by SentinelX response system."

    )


    return {

        "success": True,

        "message":
            "IP address blocked successfully.",

        "record": block_record

    }


def unblock_ip(ip_address):

    blocked_ips = load_blocked_ips()

    updated_ips = [

        item

        for item in blocked_ips

        if item["ip_address"] != ip_address

    ]


    if len(updated_ips) == len(blocked_ips):

        return {

            "success": False,

            "message":
                "IP address is not currently blocked."

        }


    save_blocked_ips(
        updated_ips
    )


    add_audit_log(

        "IP_UNBLOCKED",

        ip_address,

        "IP address removed from SentinelX block list."

    )


    return {

        "success": True,

        "message":
            "IP address unblocked successfully."

    }


if __name__ == "__main__":

    print(
        "=== SentinelX Response Manager ==="
    )

    test_ip = "203.0.113.45"


    result = block_ip(
        test_ip
    )

    print(
        result["message"]
    )


    print(
        "\nBlocked IPs:"
    )

    for item in load_blocked_ips():

        print(
            f"{item['ip_address']} | "
            f"{item['status']}"
        )


    print(
        "\nAudit Logs:"
    )

    for log in load_audit_logs():

        print(
            f"{log['timestamp']} | "
            f"{log['action']} | "
            f"{log['ip_address']}"
        )