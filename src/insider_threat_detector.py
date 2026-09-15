from pathlib import Path
import pandas as pd


# ============================================================
# PROJECT PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "output"

INPUT_FILE = OUTPUT_DIR / "unified_security_dataset.csv"
OUTPUT_FILE = OUTPUT_DIR / "insider_threat_results.csv"


print("=" * 70)
print("INSIDER THREAT DETECTION ENGINE")
print("=" * 70)


# ============================================================
# LOAD UNIFIED SECURITY DATASET
# ============================================================

print("\nLoading unified security dataset...")

security = pd.read_csv(
    INPUT_FILE,
    low_memory=False
)

print("Security profiles loaded:", len(security))


# ============================================================
# REQUIRED SECURITY FEATURES
# ============================================================

numeric_columns = [
    "failed_login_count",
    "successful_login_count",
    "mfa_failure_count",
    "total_iam_events",
    "average_iam_risk",
    "maximum_iam_risk",
    "total_firewall_events",
    "firewall_deny_count",
    "firewall_threat_count",
    "total_endpoint_alerts",
    "critical_endpoint_alerts",
    "high_endpoint_alerts",
    "invalid_resolution_alerts",
    "hostname_endpoint_alerts",
    "total_bytes_sent",
    "total_bytes_received"
]


# ============================================================
# MAKE SURE NUMERIC COLUMNS ARE NUMERIC
# ============================================================

print("\nPreparing security features...")

for column in numeric_columns:

    if column in security.columns:

        security[column] = pd.to_numeric(
            security[column],
            errors="coerce"
        ).fillna(0)


# ============================================================
# INSIDER THREAT SIGNALS
# ============================================================

print("Calculating threat signals...")


# ------------------------------------------------------------
# SIGNAL 1: FAILED AUTHENTICATION
# ------------------------------------------------------------

security["signal_failed_login"] = (
    security["failed_login_count"] >= 3
).astype(int)


# ------------------------------------------------------------
# SIGNAL 2: MFA FAILURE
# ------------------------------------------------------------

security["signal_mfa_failure"] = (
    security["mfa_failure_count"] >= 2
).astype(int)


# ------------------------------------------------------------
# SIGNAL 3: HIGH IAM RISK
# ------------------------------------------------------------

security["signal_high_iam_risk"] = (
    security["average_iam_risk"] >= 70
).astype(int)


# ------------------------------------------------------------
# SIGNAL 4: FIREWALL DENIES
# ------------------------------------------------------------

security["signal_firewall_deny"] = (
    security["firewall_deny_count"] >= 5
).astype(int)


# ------------------------------------------------------------
# SIGNAL 5: FIREWALL THREATS
# ------------------------------------------------------------

security["signal_firewall_threat"] = (
    security["firewall_threat_count"] >= 1
).astype(int)


# ------------------------------------------------------------
# SIGNAL 6: ENDPOINT ALERTS
# ------------------------------------------------------------

security["signal_endpoint_alert"] = (
    security["total_endpoint_alerts"] >= 1
).astype(int)


# ------------------------------------------------------------
# SIGNAL 7: CRITICAL ENDPOINT ALERT
# ------------------------------------------------------------

security["signal_critical_endpoint"] = (
    security["critical_endpoint_alerts"] >= 1
).astype(int)


# ------------------------------------------------------------
# SIGNAL 8: HIGH ENDPOINT ALERT
# ------------------------------------------------------------

security["signal_high_endpoint"] = (
    security["high_endpoint_alerts"] >= 1
).astype(int)


# ------------------------------------------------------------
# SIGNAL 9: EXTREME IAM RISK
# ------------------------------------------------------------

security["signal_extreme_iam_risk"] = (
    security["maximum_iam_risk"] >= 90
).astype(int)


# ============================================================
# THREAT SCORE
# ============================================================

print("Calculating insider threat score...")


security["insider_threat_score"] = (

    # Authentication
    security["failed_login_count"].clip(0, 10) * 4

    +

    security["mfa_failure_count"].clip(0, 5) * 5

    +

    # IAM risk
    security["average_iam_risk"] * 0.20

    +

    # Network
    security["firewall_deny_count"].clip(0, 10) * 2

    +

    security["firewall_threat_count"].clip(0, 5) * 8

    +

    # Endpoint
    security["total_endpoint_alerts"].clip(0, 5) * 3

    +

    security["high_endpoint_alerts"].clip(0, 3) * 6

    +

    security["critical_endpoint_alerts"].clip(0, 3) * 12

    +

    # Extreme IAM risk
    security["signal_extreme_iam_risk"] * 5
)


# ============================================================
# NORMALIZE SCORE TO 0-100
# ============================================================

security["insider_threat_score"] = (
    security["insider_threat_score"]
    .clip(0, 100)
    .round(2)
)


# ============================================================
# RISK LEVEL
# ============================================================

def calculate_risk_level(score):

    if score >= 80:
        return "CRITICAL"

    elif score >= 60:
        return "HIGH"

    elif score >= 30:
        return "MEDIUM"

    else:
        return "LOW"


security["insider_risk_level"] = (
    security["insider_threat_score"]
    .apply(calculate_risk_level)
)


# ============================================================
# ZERO-TRUST ACTION
# ============================================================

def calculate_zero_trust_action(level):

    if level == "CRITICAL":
        return "BLOCK"

    elif level == "HIGH":
        return "RESTRICT"

    elif level == "MEDIUM":
        return "VERIFY"

    else:
        return "ALLOW"


security["recommended_action"] = (
    security["insider_risk_level"]
    .apply(calculate_zero_trust_action)
)


# ============================================================
# THREAT CONFIDENCE
# ============================================================

signal_columns = [
    "signal_failed_login",
    "signal_mfa_failure",
    "signal_high_iam_risk",
    "signal_firewall_deny",
    "signal_firewall_threat",
    "signal_endpoint_alert",
    "signal_critical_endpoint",
    "signal_high_endpoint",
    "signal_extreme_iam_risk"
]


security["security_signal_count"] = (
    security[signal_columns]
    .sum(axis=1)
)


def calculate_confidence(signal_count):

    if signal_count >= 6:
        return "VERY HIGH"

    elif signal_count >= 4:
        return "HIGH"

    elif signal_count >= 2:
        return "MEDIUM"

    else:
        return "LOW"


security["threat_confidence"] = (
    security["security_signal_count"]
    .apply(calculate_confidence)
)


# ============================================================
# INSIDER THREAT CLASSIFICATION
# ============================================================

def classify_threat(row):

    score = row["insider_threat_score"]
    signals = row["security_signal_count"]

    # Strong multi-source evidence
    if score >= 70 and signals >= 3:
        return "LIKELY INSIDER THREAT"

    # Moderate evidence
    elif score >= 50 and signals >= 2:
        return "SUSPICIOUS"

    # Some abnormal behavior
    elif score >= 30:
        return "ANOMALOUS"

    else:
        return "NORMAL"


security["threat_classification"] = (
    security.apply(
        classify_threat,
        axis=1
    )
)


# ============================================================
# GENERATE EXPLANATIONS
# ============================================================

def generate_explanation(row):

    reasons = []

    # Authentication
    if row["failed_login_count"] >= 3:

        reasons.append(
            f'{int(row["failed_login_count"])} failed login attempts'
        )

    # MFA
    if row["mfa_failure_count"] >= 2:

        reasons.append(
            f'{int(row["mfa_failure_count"])} MFA failures'
        )

    # IAM risk
    if row["average_iam_risk"] >= 70:

        reasons.append(
            f'average IAM risk {row["average_iam_risk"]:.0f}/100'
        )

    # Firewall
    if row["firewall_deny_count"] >= 5:

        reasons.append(
            f'{int(row["firewall_deny_count"])} firewall DENY events'
        )

    # Firewall threat
    if row["firewall_threat_count"] >= 1:

        reasons.append(
            f'{int(row["firewall_threat_count"])} firewall threat events'
        )

    # Endpoint
    if row["total_endpoint_alerts"] >= 1:

        reasons.append(
            f'{int(row["total_endpoint_alerts"])} endpoint alerts'
        )

    # High endpoint
    if row["high_endpoint_alerts"] >= 1:

        reasons.append(
            f'{int(row["high_endpoint_alerts"])} high-severity endpoint alerts'
        )

    # Critical endpoint
    if row["critical_endpoint_alerts"] >= 1:

        reasons.append(
            f'{int(row["critical_endpoint_alerts"])} critical endpoint alerts'
        )

    # Extreme IAM
    if row["maximum_iam_risk"] >= 90:

        reasons.append(
            f'maximum IAM risk {row["maximum_iam_risk"]:.0f}/100'
        )

    # No reasons
    if not reasons:

        return "No significant security anomalies detected."

    return " + ".join(reasons)


security["threat_explanation"] = (
    security.apply(
        generate_explanation,
        axis=1
    )
)


# ============================================================
# PRIORITY
# ============================================================

def calculate_priority(level):

    if level == "CRITICAL":
        return 1

    elif level == "HIGH":
        return 2

    elif level == "MEDIUM":
        return 3

    else:
        return 4


security["priority"] = (
    security["insider_risk_level"]
    .apply(calculate_priority)
)


# ============================================================
# SORT RESULTS
# ============================================================

security = security.sort_values(
    by=[
        "priority",
        "insider_threat_score"
    ],
    ascending=[
        True,
        False
    ]
)


# ============================================================
# SAVE RESULTS
# ============================================================

security.to_csv(
    OUTPUT_FILE,
    index=False
)


# ============================================================
# DASHBOARD SUMMARY
# ============================================================

print("\n" + "=" * 70)
print("INSIDER THREAT DETECTION SUMMARY")
print("=" * 70)


print("\nTotal users analyzed:")
print(len(security))


print("\nThreat classification:")
print(
    security["threat_classification"]
    .value_counts()
)


print("\nRisk levels:")
print(
    security["insider_risk_level"]
    .value_counts()
)


print("\nRecommended Zero-Trust actions:")
print(
    security["recommended_action"]
    .value_counts()
)


print("\nThreat confidence:")
print(
    security["threat_confidence"]
    .value_counts()
)


# ============================================================
# TOP 20 HIGH-RISK USERS
# ============================================================

print("\n" + "=" * 70)
print("TOP 20 HIGH-RISK USERS")
print("=" * 70)


top_columns = [
    "user_id",
    "username",
    "department",
    "role",
    "failed_login_count",
    "mfa_failure_count",
    "average_iam_risk",
    "firewall_deny_count",
    "firewall_threat_count",
    "total_endpoint_alerts",
    "critical_endpoint_alerts",
    "insider_threat_score",
    "insider_risk_level",
    "threat_classification",
    "recommended_action",
    "threat_confidence"
]


top_columns = [
    column
    for column in top_columns
    if column in security.columns
]


print(
    security[
        top_columns
    ]
    .head(20)
    .to_string(index=False)
)


# ============================================================
# EXAMPLE THREAT EXPLANATIONS
# ============================================================

print("\n" + "=" * 70)
print("THREAT EXPLANATIONS")
print("=" * 70)


high_risk_users = security[
    security["insider_risk_level"].isin(
        ["HIGH", "CRITICAL"]
    )
].head(10)


if len(high_risk_users) == 0:

    print("\nNo HIGH or CRITICAL users detected.")

else:

    for _, row in high_risk_users.iterrows():

        print("\n----------------------------------------")

        print(
            "User:",
            row.get("user_id", "Unknown")
        )

        print(
            "Username:",
            row.get("username", "Unknown")
        )

        print(
            "Department:",
            row.get("department", "Unknown")
        )

        print(
            "Threat Score:",
            row["insider_threat_score"]
        )

        print(
            "Risk Level:",
            row["insider_risk_level"]
        )

        print(
            "Classification:",
            row["threat_classification"]
        )

        print(
            "Confidence:",
            row["threat_confidence"]
        )

        print(
            "Action:",
            row["recommended_action"]
        )

        print(
            "Why:",
            row["threat_explanation"]
        )


# ============================================================
# FINAL MESSAGE
# ============================================================

print("\n" + "=" * 70)
print("INSIDER THREAT DETECTION COMPLETE")
print("=" * 70)

print("\nResults saved to:")

print(OUTPUT_FILE)

print("\nNext stage:")
print("ZERO-TRUST SECURITY DASHBOARD")

print("=" * 70)