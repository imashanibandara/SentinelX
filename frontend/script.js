const API_BASE_URL = "http://127.0.0.1:5000";


// ===============================
// Store Risk Assessments
// ===============================
let riskAssessments = [];
let selectedAlertId = null;
let securityLogs = [];

// ===============================
// Load Dashboard Summary
// ===============================
async function loadSummary() {
    try {
        const response = await fetch(`${API_BASE_URL}/api/summary`);

        if (!response.ok) {
            throw new Error("Failed to load summary");
        }

        const data = await response.json();

        document.getElementById("total-alerts").textContent =
            data.total_alerts;

        document.getElementById("critical-alerts").textContent =
            data.critical;

        document.getElementById("high-alerts").textContent =
            data.high;

        document.getElementById("medium-alerts").textContent =
            data.medium;

        document.getElementById("risk-count").textContent =
            data.total_alerts;

        document.getElementById("risk-critical").textContent =
            data.critical;

        document.getElementById("risk-high").textContent =
            data.high;

        document.getElementById("risk-medium").textContent =
            data.medium;

        document.getElementById("risk-low").textContent =
            data.low;

                // Update Security Analytics Chart

        document.getElementById("chart-critical").textContent =
            data.critical;

        document.getElementById("chart-high").textContent =
            data.high;

        document.getElementById("chart-medium").textContent =
            data.medium;

        document.getElementById("chart-low").textContent =
            data.low;


        // Calculate total alerts

        const totalAlerts = data.total_alerts;


        // Calculate chart percentages

        let criticalPercentage = 0;
        let highPercentage = 0;
        let mediumPercentage = 0;
        let lowPercentage = 0;


        if (totalAlerts > 0) {

            criticalPercentage =
                (data.critical / totalAlerts) * 100;

            highPercentage =
                (data.high / totalAlerts) * 100;

            mediumPercentage =
                (data.medium / totalAlerts) * 100;

            lowPercentage =
                (data.low / totalAlerts) * 100;
        }


        // Update chart bars

        document.getElementById("bar-critical").style.width =
            `${criticalPercentage}%`;

        document.getElementById("bar-high").style.width =
            `${highPercentage}%`;

        document.getElementById("bar-medium").style.width =
            `${mediumPercentage}%`;

        document.getElementById("bar-low").style.width =
            `${lowPercentage}%`;

    } catch (error) {

        console.error("Summary loading error:", error);

    }
}


// ===============================
// Load Security Alerts
// ===============================
async function loadAlerts() {

    try {

        const response =
            await fetch(`${API_BASE_URL}/api/alerts`);

        if (!response.ok) {
            throw new Error("Failed to load alerts");
        }

        const alerts = await response.json();

        const tableBody =
            document.getElementById("alerts-table");

        tableBody.innerHTML = "";

        if (alerts.length === 0) {

            tableBody.innerHTML = `
                <tr>
                    <td colspan="6">
                        No security alerts detected.
                    </td>
                </tr>
            `;

            return;
        }

        // Store alerts globally
        window.sentinelAlerts = alerts;

        // Display alerts
        displayAlerts(alerts);

    } catch (error) {

        console.error(
            "Alert loading error:",
            error
        );

        document.getElementById("alerts-table").innerHTML = `
            <tr>
                <td colspan="6">
                    Unable to load security alerts.
                </td>
            </tr>
        `;
    }
}

function displayAlerts(alerts) {

    const tableBody =
        document.getElementById("alerts-table");

    tableBody.innerHTML = "";

    if (alerts.length === 0) {

        tableBody.innerHTML = `
            <tr>
                <td colspan="6">
                    No matching security alerts found.
                </td>
            </tr>
        `;

        return;
    }

    alerts.forEach(alert => {

        const row =
            document.createElement("tr");

        row.innerHTML = `
            <td>
                ${alert.alert_id}
            </td>

            <td>
                ${alert.alert_type}
            </td>

            <td>
                ${alert.source_ip}
            </td>

            <td>
                ${alert.attempts}
            </td>

            <td>
                <span class="severity-badge">
                    ${alert.severity}
                </span>

                <button
                    class="view-button"
                    onclick="showAlertDetails(${alert.alert_id})"
                >
                    View
                </button>
            </td>

            <td>
                <span
                    class="incident-status"
                    id="incident-status-${alert.alert_id}"
                >
                    Loading...
                </span>
            </td>
        `;

        tableBody.appendChild(row);

    });

    // Load current incident statuses
    loadIncidentStatuses();
}

function filterAlerts() {

    const searchInput =
        document.getElementById(
            "alert-search"
        ).value.toLowerCase();

    const severityFilter =
        document.getElementById(
            "alert-severity-filter"
        ).value;

    const statusFilter =
        document.getElementById(
            "alert-status-filter"
        ).value;

    const sortOption =
        document.getElementById(
            "alert-sort"
        ).value;


    let filteredAlerts =
        [...window.sentinelAlerts];


    // ===============================
    // Search Filter
    // ===============================

    filteredAlerts =
        filteredAlerts.filter(alert => {

            const matchesSearch =
                alert.alert_type
                    .toLowerCase()
                    .includes(searchInput) ||

                alert.source_ip
                    .toLowerCase()
                    .includes(searchInput);

            return matchesSearch;
        });


    // ===============================
    // Severity Filter
    // ===============================

    if (severityFilter !== "all") {

        filteredAlerts =
            filteredAlerts.filter(
                alert =>
                    alert.severity === severityFilter
            );
    }


    // ===============================
    // Status Filter
    // ===============================

    if (statusFilter !== "all") {

        const incidents =
            window.sentinelIncidents || [];

        filteredAlerts =
            filteredAlerts.filter(alert => {

                const incident =
                    incidents.find(
                        item =>
                            item.alert_id ===
                            alert.alert_id
                    );

                return incident &&
                    incident.status === statusFilter;
            });
    }


    // ===============================
    // Sorting
    // ===============================

    if (sortOption === "id-desc") {

        filteredAlerts.sort(
            (a, b) =>
                b.alert_id - a.alert_id
        );
    }

    else if (sortOption === "id-asc") {

        filteredAlerts.sort(
            (a, b) =>
                a.alert_id - b.alert_id
        );
    }

    else if (sortOption === "risk-desc") {

        filteredAlerts.sort(
            (a, b) =>
                getRiskScore(b.alert_id) -
                getRiskScore(a.alert_id)
        );
    }

    else if (sortOption === "risk-asc") {

        filteredAlerts.sort(
            (a, b) =>
                getRiskScore(a.alert_id) -
                getRiskScore(b.alert_id)
        );
    }


    displayAlerts(filteredAlerts);
}


function getRiskScore(alertId) {

    const assessment =
        riskAssessments.find(
            item =>
                item.alert_id === alertId
        );

    if (!assessment) {
        return 0;
    }

    return assessment.risk_score;
}

// ===============================
// Load Risk Assessments
// ===============================
async function loadRiskAssessments() {

    try {

        const response =
            await fetch(
                `${API_BASE_URL}/api/risk-assessments`
            );

        if (!response.ok) {
            throw new Error(
                "Failed to load risk assessments"
            );
        }

        riskAssessments =
            await response.json();

        console.log(
            "Risk assessments:",
            riskAssessments
        );

    } catch (error) {

        console.error(
            "Risk assessment loading error:",
            error
        );

    }
}

// =========================================
// Load Threat Intelligence
// =========================================

async function loadThreatIntelligence() {

    try {

        const response =
            await fetch(
                `${API_BASE_URL}/api/threat-intelligence`
            );

        if (!response.ok) {

            throw new Error(
                "Failed to load threat intelligence"
            );
        }

        const threats =
            await response.json();

        const tableBody =
            document.getElementById(
                "threat-intelligence-body"
            );

        tableBody.innerHTML = "";

        threats.forEach(threat => {

            const row =
                document.createElement("tr");

            row.innerHTML = `
                <td>${threat.ip_address}</td>

                <td>
                    <span class="reputation-badge">
                        ${threat.reputation}
                    </span>
                </td>

                <td>${threat.threat_type}</td>

                <td>${threat.confidence}%</td>

                <td>
                    <span class="status-badge">
                        ${threat.status}
                    </span>
                </td>
            `;

            tableBody.appendChild(row);

        });

    } catch (error) {

        console.error(
            "Threat intelligence error:",
            error
        );
    }
}


// =========================================
// Load Incident Status
// =========================================

async function loadIncidentStatuses() {

    try {

        const response =
            await fetch(
                `${API_BASE_URL}/api/incidents`
            );

        if (!response.ok) {

            throw new Error(
                "Failed to load incidents"
            );
        }

        const incidents =
            await response.json();

        window.sentinelIncidents = incidents;

        incidents.forEach(incident => {

            const statusElement =
                document.getElementById(
                    `incident-status-${incident.alert_id}`
                );

            if (statusElement) {

                statusElement.textContent =
                    incident.status;
            }

        });

    } catch (error) {

        console.error(
            "Incident status error:",
            error
        );
    }
}


// ===============================
// Show Alert Details
// ===============================
function showAlertDetails(alertId) {

    selectedAlertId = alertId;

    loadIncidentDetails(alertId);
    const selectedAlert =
    window.sentinelAlerts.find(
        alert => alert.alert_id === alertId
    );

    if (selectedAlert) {

        updateIPResponseStatus(
            selectedAlert.source_ip
        );

    }

    const assessment =
        riskAssessments.find(
            item => item.alert_id === alertId
        );

    if (!assessment) {

        console.error(
            "Risk assessment not found for alert:",
            alertId
        );

        return;
    }


    document.getElementById(
        "detail-alert-id"
    ).textContent =
        `#${assessment.alert_id}`;


    document.getElementById(
        "detail-alert-type"
    ).textContent =
        assessment.alert_type;


    document.getElementById(
        "detail-source-ip"
    ).textContent =
        assessment.source_ip;


    document.getElementById(
        "detail-attempts"
    ).textContent =
        assessment.attempts;


    document.getElementById(
        "detail-severity"
    ).textContent =
        assessment.severity;


    document.getElementById(
        "detail-risk-score"
    ).textContent =
        `${assessment.risk_score}/100`;


    document.getElementById(
        "detail-risk-level"
    ).textContent =
        assessment.risk_level;


    document.getElementById(
        "detail-timestamp"
    ).textContent =
        assessment.timestamp;


    const detailsPanel =
        document.getElementById("alert-details");


    detailsPanel.classList.remove("hidden");

    detailsPanel.scrollIntoView({
        behavior: "smooth",
        block: "start"
    });
}


// ===============================
// Close Alert Details
// ===============================
document.getElementById(
    "close-details"
).addEventListener(
    "click",
    function () {

        document
            .getElementById("alert-details")
            .classList.add("hidden");

    }
);


// ===============================
// Load Complete Dashboard
// ===============================
async function loadDashboard() {

    await loadSummary();

    await loadAlerts();

    await loadRiskAssessments();

    await loadThreatIntelligence();

    await loadIncidentStatuses();

    await loadSecurityLogs();

    await loadAnalytics();

    console.log(
        "SentinelX dashboard loaded successfully."
    );
}


// ===============================
// Start Application
// ===============================
loadDashboard();



// ===============================
// Update Incident
// ===============================
async function updateIncident() {

    if (!selectedAlertId) {
        return;
    }

    const status =
        document.getElementById(
            "incident-status-select"
        ).value;

    const notes =
        document.getElementById(
            "incident-notes"
        ).value;

    const message =
        document.getElementById(
            "incident-update-message"
        );

    try {

        const response = await fetch(
            `${API_BASE_URL}/api/incidents/${selectedAlertId}`,
            {
                method: "PUT",

                headers: {
                    "Content-Type": "application/json"
                },

                body: JSON.stringify({
                    status: status,
                    notes: notes
                })
            }
        );

        const result = await response.json();

        if (!response.ok) {
            throw new Error(
                result.error ||
                "Failed to update incident"
            );
        }

        message.textContent =
            "Incident updated successfully.";

        await loadIncidentStatuses();

    } catch (error) {

        console.error(
            "Incident update error:",
            error
        );

        message.textContent =
            "Unable to update incident.";
    }
}

// ===============================
// Load Incident Details
// ===============================
async function loadIncidentDetails(alertId) {


    try {

        const response = await fetch(
            `${API_BASE_URL}/api/incidents`
        );

        if (!response.ok) {
            throw new Error(
                "Failed to load incident details"
            );
        }

        const incidents = await response.json();

        const incident = incidents.find(
            item => item.alert_id === alertId
        );

        if (!incident) {
            return;
        }

        document.getElementById(
            "incident-status-select"
        ).value = incident.status;

        document.getElementById(
            "incident-notes"
        ).value = incident.notes || "";

        document.getElementById(
            "incident-update-message"
        ).textContent = "";

    } catch (error) {

        console.error(
            "Incident details error:",
            error
        );
    }
}


// ===============================
// Update Incident Button
// ===============================

document.getElementById(
    "update-incident-button"
).addEventListener(
    "click",
    updateIncident
);

// =========================================
// Load Security Activity
// =========================================

async function loadSecurityLogs() {

    try {

        const response =
            await fetch(
                `${API_BASE_URL}/api/security-logs`
            );

        if (!response.ok) {
            throw new Error(
                "Failed to load security logs"
            );
        }

        const logs =
            await response.json();

        securityLogs = logs;

        displaySecurityLogs(logs);

    } catch (error) {

        console.error(
            "Security logs error:",
            error
        );

        document.getElementById(
            "security-logs-body"
        ).innerHTML = `
            <tr>
                <td colspan="4">
                    Unable to load security activity.
                </td>
            </tr>
        `;
    }
}

// =========================================
// Filter Security Activity
// =========================================

function filterSecurityLogs() {

    const searchInput =
        document.getElementById(
            "activity-search"
        ).value.toLowerCase();

    const eventFilter =
        document.getElementById(
            "activity-event-filter"
        ).value;

    const filteredLogs =
        securityLogs.filter(log => {

            const matchesSearch =
                log.username.toLowerCase()
                    .includes(searchInput) ||

                log.source_ip.toLowerCase()
                    .includes(searchInput);

            const matchesEvent =
                eventFilter === "all" ||
                log.event_type === eventFilter;

            return matchesSearch && matchesEvent;
        });

    displaySecurityLogs(filteredLogs);
}

// =========================================
// Display Security Activity
// =========================================

function displaySecurityLogs(logs) {

    const tableBody =
        document.getElementById(
            "security-logs-body"
        );

    tableBody.innerHTML = "";

    if (logs.length === 0) {

        tableBody.innerHTML = `
            <tr>
                <td colspan="4">
                    No matching security activity found.
                </td>
            </tr>
        `;

        return;
    }

    logs.forEach(log => {

        const row =
            document.createElement("tr");

        row.innerHTML = `
            <td>
                ${log.timestamp}
            </td>

            <td>
                ${log.username}
            </td>

            <td>
                ${log.source_ip}
            </td>

           <td>
                <span
                    class="event-badge ${
                        log.event_type === "login_failed"
                            ? "event-failed"
                            : "event-success"
                    }"
                >
                    ${log.event_type}
                </span>
            </td>
        `;

        tableBody.appendChild(row);

    });
}


// =========================================
// Security Activity Filters
// =========================================

document.addEventListener(
    "DOMContentLoaded",
    function () {

        const searchInput =
            document.getElementById(
                "activity-search"
            );

        const eventFilter =
            document.getElementById(
                "activity-event-filter"
            );

        if (searchInput) {

            searchInput.addEventListener(
                "input",
                filterSecurityLogs
            );

        }

        if (eventFilter) {

            eventFilter.addEventListener(
                "change",
                filterSecurityLogs
            );

        }

    }
);

document.addEventListener(
    "DOMContentLoaded",
    function () {

        const alertSearch =
            document.getElementById(
                "alert-search"
            );

        const severityFilter =
            document.getElementById(
                "alert-severity-filter"
            );

        const statusFilter =
            document.getElementById(
                "alert-status-filter"
            );

        const alertSort =
            document.getElementById(
                "alert-sort"
            );


        if (alertSearch) {

            alertSearch.addEventListener(
                "input",
                filterAlerts
            );
        }


        if (severityFilter) {

            severityFilter.addEventListener(
                "change",
                filterAlerts
            );
        }


        if (statusFilter) {

            statusFilter.addEventListener(
                "change",
                filterAlerts
            );
        }


        if (alertSort) {

            alertSort.addEventListener(
                "change",
                filterAlerts
            );
        }

    }
);


// =========================================
// IP Investigation
// =========================================

function investigateIP() {

    const ipInput =
        document.getElementById(
            "investigation-ip"
        );

    const ip =
        ipInput.value.trim();

    const result =
        document.getElementById(
            "investigation-result"
        );

    const message =
        document.getElementById(
            "investigation-message"
        );

    // Clear previous message
    message.textContent = "";

    // Validate IP input
    if (!ip) {

        result.classList.add("hidden");

        message.textContent =
            "Please enter an IP address.";

        return;
    }


    // =========================================
    // Find related security logs
    // =========================================

    const relatedLogs =
        securityLogs.filter(
            log =>
                log.source_ip === ip
        );


    // =========================================
    // Count events
    // =========================================

    const totalEvents =
        relatedLogs.length;

    const failedLogins =
        relatedLogs.filter(
            log =>
                log.event_type ===
                "login_failed"
        ).length;

    const successfulLogins =
        relatedLogs.filter(
            log =>
                log.event_type ===
                "login_success"
        ).length;


    // =========================================
    // Find threat intelligence
    // =========================================

    fetch(
        `${API_BASE_URL}/api/threat-intelligence`
    )
        .then(response => response.json())

        .then(threats => {

            const threat =
                threats.find(
                    item =>
                        item.ip_address === ip
                );


            // =========================================
            // Find related risk assessment
            // =========================================

            const relatedAlert =
                riskAssessments.find(
                    assessment =>
                        assessment.source_ip === ip
                );


            // =========================================
            // Update IP
            // =========================================

            document.getElementById(
                "investigation-ip-value"
            ).textContent = ip;


            // =========================================
            // Reputation
            // =========================================

            document.getElementById(
                "investigation-reputation"
            ).textContent =
                threat
                    ? threat.reputation
                    : "Unknown";


            // =========================================
            // Statistics
            // =========================================

            document.getElementById(
                "investigation-total-events"
            ).textContent =
                totalEvents;


            document.getElementById(
                "investigation-failed-logins"
            ).textContent =
                failedLogins;


            document.getElementById(
                "investigation-success-logins"
            ).textContent =
                successfulLogins;


            document.getElementById(
                "investigation-risk-score"
            ).textContent =
                relatedAlert
                    ? `${relatedAlert.risk_score}/100`
                    : "0/100";


            // =========================================
            // Threat details
            // =========================================

            document.getElementById(
                "investigation-threat-type"
            ).textContent =
                threat
                    ? threat.threat_type
                    : "No threat intelligence";


            document.getElementById(
                "investigation-confidence"
            ).textContent =
                threat
                    ? `${threat.confidence}%`
                    : "N/A";


            document.getElementById(
                "investigation-status"
            ).textContent =
                threat
                    ? threat.status
                    : "Unknown";


            // =========================================
            // Related Events Table
            // =========================================

            const eventsBody =
                document.getElementById(
                    "investigation-events-body"
                );

            eventsBody.innerHTML = "";


            if (relatedLogs.length === 0) {

                eventsBody.innerHTML = `
                    <tr>
                        <td colspan="3">
                            No security events found for this IP.
                        </td>
                    </tr>
                `;

            } else {

                relatedLogs.forEach(log => {

                    const row =
                        document.createElement("tr");


                    row.innerHTML = `
                        <td>
                            ${log.timestamp}
                        </td>

                        <td>
                            ${log.username}
                        </td>

                        <td>
                            <span class="event-badge ${
                                log.event_type === "login_failed"
                                    ? "event-failed"
                                    : "event-success"
                            }">
                                ${log.event_type}
                            </span>
                        </td>
                    `;


                    eventsBody.appendChild(row);

                });

            }


            // =========================================
            // Show investigation panel
            // =========================================

            result.classList.remove("hidden");

            result.scrollIntoView({
                behavior: "smooth",
                block: "start"
            });

        })

        .catch(error => {

            console.error(
                "IP investigation error:",
                error
            );

            message.textContent =
                "Unable to investigate IP address.";

        });
}


// =========================================
// Investigate IP Button
// =========================================

document.getElementById(
    "investigate-ip-button"
).addEventListener(
    "click",
    investigateIP
);


// =========================================
// Enter Key Support
// =========================================

document.getElementById(
    "investigation-ip"
).addEventListener(
    "keypress",
    function (event) {

        if (event.key === "Enter") {

            investigateIP();

        }

    }
);


// =========================================
// Advanced Security Analytics
// =========================================

async function loadAnalytics() {

    try {

        const response =
            await fetch(
                `${API_BASE_URL}/api/analytics`
            );

        if (!response.ok) {

            throw new Error(
                "Failed to load analytics"
            );

        }

        const data =
            await response.json();


        // =====================================
        // Login Statistics
        // =====================================

        const failed =
            data.login_statistics.failed;

        const success =
            data.login_statistics.success;

        const totalEvents =
            failed + success;


        document.getElementById(
            "analytics-failed-logins"
        ).textContent = failed;


        document.getElementById(
            "analytics-success-logins"
        ).textContent = success;


        document.getElementById(
            "analytics-total-events"
        ).textContent = totalEvents;


        // =====================================
        // Risk Distribution
        // =====================================

        document.getElementById(
            "analytics-critical"
        ).textContent =
            data.risk_distribution.CRITICAL;


        document.getElementById(
            "analytics-high"
        ).textContent =
            data.risk_distribution.HIGH;


        document.getElementById(
            "analytics-medium"
        ).textContent =
            data.risk_distribution.MEDIUM;


        document.getElementById(
            "analytics-low"
        ).textContent =
            data.risk_distribution.LOW;


        // =====================================
        // Attack Type Distribution
        // =====================================

        const attackList =
            document.getElementById(
                "attack-type-list"
            );

        attackList.innerHTML = "";


        const attackTypes =
            data.attack_types;


        const sortedAttackTypes =
            Object.entries(
                attackTypes
            ).sort(
                (a, b) => b[1] - a[1]
            );


        if (sortedAttackTypes.length === 0) {

            attackList.innerHTML = `
                <p>
                    No attack activity detected.
                </p>
            `;

        } else {

            sortedAttackTypes.forEach(
                ([attackType, count]) => {

                    const row =
                        document.createElement(
                            "div"
                        );

                    row.className =
                        "attack-type-row";


                    row.innerHTML = `

                        <span
                            class="attack-type-name"
                        >
                            ${attackType}
                        </span>

                        <span
                            class="attack-type-count"
                        >
                            ${count}
                        </span>

                    `;


                    attackList.appendChild(row);

                }
            );

        }


        // =====================================
        // Top Source IPs
        // =====================================

        const ipList =
            document.getElementById(
                "top-ip-list"
            );

        ipList.innerHTML = "";


        const topIPs =
            data.top_suspicious_ips;


        if (topIPs.length === 0) {

            ipList.innerHTML = `
                <p>
                    No source activity detected.
                </p>
            `;

        } else {

            topIPs.forEach(
                item => {

                    const row =
                        document.createElement(
                            "div"
                        );

                    row.className =
                        "top-ip-row";


                    row.innerHTML = `

                        <span
                            class="top-ip-address"
                        >
                            ${item.ip}
                        </span>

                        <span
                            class="top-ip-events"
                        >
                            ${item.events} events
                        </span>

                    `;


                    ipList.appendChild(row);

                }
            );

        }


        console.log(
            "Security analytics loaded successfully."
        );


    } catch (error) {

        console.error(
            "Analytics loading error:",
            error
        );

    }

}


// =========================================
// IP Response Controls
// =========================================

async function loadBlockedIPs() {

    try {

        const response =
            await fetch(
                `${API_BASE_URL}/api/blocked-ips`
            );

        if (!response.ok) {
            throw new Error(
                "Failed to load blocked IPs"
            );
        }

        return await response.json();

    } catch (error) {

        console.error(
            "Blocked IP loading error:",
            error
        );

        return [];
    }
}


async function updateIPResponseStatus(
    ipAddress
) {

    const blockedIPs =
        await loadBlockedIPs();

    const blocked =
        blockedIPs.some(
            item =>
                item.ip_address === ipAddress
        );


    document.getElementById(
        "response-ip-address"
    ).textContent = ipAddress;


    document.getElementById(
        "response-block-status"
    ).textContent =
        blocked
            ? "Blocked"
            : "Not Blocked";


    document.getElementById(
        "ip-response-status"
    ).textContent =
        blocked
            ? "BLOCKED"
            : "MONITORING";
}


async function blockSelectedIP() {

    const ip =
        document.getElementById(
            "response-ip-address"
        ).textContent;

    if (!ip || ip === "-") {
        return;
    }


    const message =
        document.getElementById(
            "ip-response-message"
        );


    try {

        const response =
            await fetch(
                `${API_BASE_URL}/api/response/block`,
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        ip_address: ip
                    })
                }
            );


        const result =
            await response.json();


        if (!response.ok) {

            throw new Error(
                result.message ||
                result.error ||
                "Unable to block IP"
            );

        }


        message.textContent =
            result.message;


        await updateIPResponseStatus(
            ip
        );


    } catch (error) {

        console.error(
            "Block IP error:",
            error
        );

        message.textContent =
            error.message;

    }
}


async function unblockSelectedIP() {

    const ip =
        document.getElementById(
            "response-ip-address"
        ).textContent;

    if (!ip || ip === "-") {
        return;
    }


    const message =
        document.getElementById(
            "ip-response-message"
        );


    try {

        const response =
            await fetch(
                `${API_BASE_URL}/api/response/unblock`,
                {
                    method: "POST",

                    headers: {
                        "Content-Type":
                            "application/json"
                    },

                    body: JSON.stringify({
                        ip_address: ip
                    })
                }
            );


        const result =
            await response.json();


        if (!response.ok) {

            throw new Error(
                result.message ||
                result.error ||
                "Unable to unblock IP"
            );

        }


        message.textContent =
            result.message;


        await updateIPResponseStatus(
            ip
        );


    } catch (error) {

        console.error(
            "Unblock IP error:",
            error
        );

        message.textContent =
            error.message;

    }
}


document.getElementById(
    "block-ip-button"
).addEventListener(
    "click",
    blockSelectedIP
);


document.getElementById(
    "unblock-ip-button"
).addEventListener(
    "click",
    unblockSelectedIP
);


// =========================================
// SIDEBAR NAVIGATION
// =========================================

const navItems = document.querySelectorAll(".nav-item");

navItems.forEach(item => {
    item.addEventListener("click", function () {

        navItems.forEach(nav => {
            nav.classList.remove("active");
        });

        this.classList.add("active");
    });
});


// =========================================
// ACTIVE NAVIGATION ON SCROLL
// =========================================

const sections = [
    {
        id: "dashboard-section",
        nav: document.querySelector('.nav-item[href="#dashboard-section"]')
    },
    {
        id: "alerts-section",
        nav: document.querySelector('.nav-item[href="#alerts-section"]')
    },
    {
        id: "threats-section",
        nav: document.querySelector('.nav-item[href="#threats-section"]')
    },
    {
        id: "activity-section",
        nav: document.querySelector('.nav-item[href="#activity-section"]')
    }
];

window.addEventListener("scroll", function () {

    let currentSection = "dashboard-section";

    sections.forEach(section => {

        const element = document.getElementById(section.id);

        if (!element) return;

        const sectionTop = element.getBoundingClientRect().top;

        if (sectionTop <= 180) {
            currentSection = section.id;
        }
    });

    navItems.forEach(nav => {
        nav.classList.remove("active");
    });

    const activeSection = sections.find(
        section => section.id === currentSection
    );

    if (activeSection && activeSection.nav) {
        activeSection.nav.classList.add("active");
    }
});

// =========================================
// SENTINELX LIVE MONITORING
// =========================================

async function refreshLiveDashboard() {
    try {
        await loadSummary();
        await loadAlerts();
        await loadRiskAssessments();
        await loadThreatIntelligence();
        await loadIncidentStatuses();
        await loadAnalytics();

        updateLiveStatus(true);

    } catch (error) {
        console.error(
            "Live dashboard refresh failed:",
            error
        );

        updateLiveStatus(false);
    }
}

function updateLiveStatus(isOnline) {

    const statusElement =
        document.querySelector(".system-status");

    if (!statusElement) return;

    if (isOnline) {

        statusElement.innerHTML = `
            <span class="status-dot"></span>
            Operational
        `;

        statusElement.classList.remove("offline");

    } else {

        statusElement.innerHTML = `
            <span class="status-dot offline-dot"></span>
            Connection Error
        `;

        statusElement.classList.add("offline");
    }
}


// Refresh dashboard every 30 seconds
setInterval(
    refreshLiveDashboard,
    30000
);