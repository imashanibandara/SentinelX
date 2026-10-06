import json


# =========================================
# Load Threat Intelligence Data
# =========================================

def load_threat_intelligence():

    with open(
        "data/threat_intelligence.json",
        "r"
    ) as file:

        return json.load(file)


# =========================================
# Find IP Intelligence
# =========================================

def get_ip_intelligence(ip_address):

    threat_data = load_threat_intelligence()

    for threat in threat_data:

        if threat["ip_address"] == ip_address:

            return threat

    return None


# =========================================
# Test Threat Intelligence
# =========================================

if __name__ == "__main__":

    print("=== SentinelX Threat Intelligence ===")

    test_ips = [
        "203.0.113.45",
        "203.0.113.99",
        "192.168.1.50"
    ]

    for ip in test_ips:

        result = get_ip_intelligence(ip)

        print(
            f"\nIP Address: {ip}"
        )

        if result:

            print(
                f"Reputation: "
                f"{result['reputation']}"
            )

            print(
                f"Threat Type: "
                f"{result['threat_type']}"
            )

            print(
                f"Confidence: "
                f"{result['confidence']}%"
            )

            print(
                f"Status: "
                f"{result['status']}"
            )

        else:

            print(
                "No threat intelligence found."
            )