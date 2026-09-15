from pathlib import Path
import pandas as pd


# ============================================================
# PROJECT PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "output"

print("=" * 70)
print("ZERO-TRUST SECURITY CORRELATION")
print("=" * 70)


# ============================================================
# FILE PATHS
# ============================================================

IAM_FILE = OUTPUT_DIR / "cleaned_iam.csv"
FIREWALL_FILE = OUTPUT_DIR / "cleaned_firewall.csv"
ENDPOINT_FILE = OUTPUT_DIR / "cleaned_endpoint.csv"
IDENTITY_FILE = OUTPUT_DIR / "cleaned_identity.csv"


# ============================================================
# LOAD CLEANED DATA
# ============================================================

print("\nLoading cleaned telemetry...")


iam = pd.read_csv(
    IAM_FILE,
    low_memory=False
)

firewall = pd.read_csv(
    FIREWALL_FILE,
    low_memory=False
)

endpoint = pd.read_csv(
    ENDPOINT_FILE,
    low_memory=False
)

identity = pd.read_csv(
    IDENTITY_FILE,
    low_memory=False
)


print("\nLoaded records:")
print("IAM       :", len(iam))
print("Firewall  :", len(firewall))
print("Endpoint  :", len(endpoint))
print("Identity  :", len(identity))


# ============================================================
# NORMALIZE JOIN COLUMNS
# ============================================================

print("\nNormalizing correlation keys...")


# ------------------------------------------------------------
# IAM
# ------------------------------------------------------------

if "user_id" in iam.columns:

    iam["user_id"] = (
        iam["user_id"]
        .astype("string")
        .str.strip()
        .str.upper()
    )


if "hostname" in iam.columns:

    iam["hostname"] = (
        iam["hostname"]
        .astype("string")
        .str.strip()
        .str.upper()
        .str.replace("_", "-", regex=False)
    )


# ------------------------------------------------------------
# FIREWALL
# ------------------------------------------------------------

if "hostname" in firewall.columns:

    firewall["hostname"] = (
        firewall["hostname"]
        .astype("string")
        .str.strip()
        .str.upper()
        .str.replace("_", "-", regex=False)
    )


# ------------------------------------------------------------
# ENDPOINT
# ------------------------------------------------------------

if "user_id" in endpoint.columns:

    endpoint["user_id"] = (
        endpoint["user_id"]
        .astype("string")
        .str.strip()
        .str.upper()
    )


if "hostname" in endpoint.columns:

    endpoint["hostname"] = (
        endpoint["hostname"]
        .astype("string")
        .str.strip()
        .str.upper()
        .str.replace("_", "-", regex=False)
    )


# ------------------------------------------------------------
# IDENTITY
# ------------------------------------------------------------

if "user_id" in identity.columns:

    identity["user_id"] = (
        identity["user_id"]
        .astype("string")
        .str.strip()
        .str.upper()
    )


if "hostname" in identity.columns:

    identity["hostname"] = (
        identity["hostname"]
        .astype("string")
        .str.strip()
        .str.upper()
        .str.replace("_", "-", regex=False)
    )


# ============================================================
# 1. BUILD IDENTITY BASE
# ============================================================

print("\nBuilding identity base...")


identity_base_columns = [
    "user_id",
    "username",
    "full_name",
    "department",
    "role",
    "location",
    "hostname",
    "device_id",
    "status",
    "hire_date",
    "termination_date",
    "manager_username"
]


# Keep only columns that actually exist
identity_base_columns = [
    column
    for column in identity_base_columns
    if column in identity.columns
]


user_profile = identity[
    identity_base_columns
].copy()


# Remove duplicate users
user_profile = user_profile.drop_duplicates(
    subset=["user_id"]
)


print(
    "Unique identity profiles:",
    len(user_profile)
)


# ============================================================
# 2. IAM SECURITY FEATURES
# ============================================================

print("\nCreating IAM security features...")


# ------------------------------------------------------------
# Failed login count
# ------------------------------------------------------------

iam_failed = (
    iam[iam["event_type"] == "login_failed"]
    .groupby("user_id")
    .size()
    .reset_index(name="failed_login_count")
)


# ------------------------------------------------------------
# Successful login count
# ------------------------------------------------------------

iam_success = (
    iam[iam["event_type"] == "login_success"]
    .groupby("user_id")
    .size()
    .reset_index(name="successful_login_count")
)


# ------------------------------------------------------------
# MFA failure count
# ------------------------------------------------------------

if "mfa_passed" in iam.columns:

    iam_mfa_failed = (
        iam[iam["mfa_passed"] == 0]
        .groupby("user_id")
        .size()
        .reset_index(name="mfa_failure_count")
    )

else:

    iam_mfa_failed = pd.DataFrame(
        columns=[
            "user_id",
            "mfa_failure_count"
        ]
    )


# ------------------------------------------------------------
# Average risk score
# ------------------------------------------------------------

if "risk_score" in iam.columns:

    iam_risk = (
        iam.groupby("user_id")["risk_score"]
        .mean()
        .reset_index(name="average_iam_risk")
    )

else:

    iam_risk = pd.DataFrame(
        columns=[
            "user_id",
            "average_iam_risk"
        ]
    )


# ------------------------------------------------------------
# Maximum risk score
# ------------------------------------------------------------

if "risk_score" in iam.columns:

    iam_max_risk = (
        iam.groupby("user_id")["risk_score"]
        .max()
        .reset_index(name="maximum_iam_risk")
    )

else:

    iam_max_risk = pd.DataFrame(
        columns=[
            "user_id",
            "maximum_iam_risk"
        ]
    )


# ------------------------------------------------------------
# Total IAM events
# ------------------------------------------------------------

iam_total = (
    iam.groupby("user_id")
    .size()
    .reset_index(name="total_iam_events")
)


# ------------------------------------------------------------
# Combine IAM features
# ------------------------------------------------------------

iam_features = iam_failed.merge(
    iam_success,
    on="user_id",
    how="outer"
)

iam_features = iam_features.merge(
    iam_mfa_failed,
    on="user_id",
    how="outer"
)

iam_features = iam_features.merge(
    iam_risk,
    on="user_id",
    how="outer"
)

iam_features = iam_features.merge(
    iam_max_risk,
    on="user_id",
    how="outer"
)

iam_features = iam_features.merge(
    iam_total,
    on="user_id",
    how="outer"
)


# ============================================================
# 3. FIREWALL SECURITY FEATURES
# ============================================================

print("Creating firewall security features...")


# ------------------------------------------------------------
# Total firewall events per hostname
# ------------------------------------------------------------

firewall_total = (
    firewall.groupby("hostname")
    .size()
    .reset_index(name="total_firewall_events")
)


# ------------------------------------------------------------
# Firewall DENY count
# ------------------------------------------------------------

if "action" in firewall.columns:

    firewall_deny = (
        firewall[firewall["action"] == "DENY"]
        .groupby("hostname")
        .size()
        .reset_index(name="firewall_deny_count")
    )

else:

    firewall_deny = pd.DataFrame(
        columns=[
            "hostname",
            "firewall_deny_count"
        ]
    )


# ------------------------------------------------------------
# Firewall threat count
# ------------------------------------------------------------

if "threat_flag" in firewall.columns:

    firewall_threat = (
        firewall[firewall["threat_flag"] == 1]
        .groupby("hostname")
        .size()
        .reset_index(name="firewall_threat_count")
    )

else:

    firewall_threat = pd.DataFrame(
        columns=[
            "hostname",
            "firewall_threat_count"
        ]
    )


# ------------------------------------------------------------
# Firewall bytes sent
# ------------------------------------------------------------

if "bytes_sent" in firewall.columns:

    firewall_sent = (
        firewall.groupby("hostname")["bytes_sent"]
        .sum()
        .reset_index(name="total_bytes_sent")
    )

else:

    firewall_sent = pd.DataFrame(
        columns=[
            "hostname",
            "total_bytes_sent"
        ]
    )


# ------------------------------------------------------------
# Firewall bytes received
# ------------------------------------------------------------

if "bytes_received" in firewall.columns:

    firewall_received = (
        firewall.groupby("hostname")["bytes_received"]
        .sum()
        .reset_index(name="total_bytes_received")
    )

else:

    firewall_received = pd.DataFrame(
        columns=[
            "hostname",
            "total_bytes_received"
        ]
    )


# ------------------------------------------------------------
# Combine firewall features
# ------------------------------------------------------------

firewall_features = firewall_total.merge(
    firewall_deny,
    on="hostname",
    how="outer"
)

firewall_features = firewall_features.merge(
    firewall_threat,
    on="hostname",
    how="outer"
)

firewall_features = firewall_features.merge(
    firewall_sent,
    on="hostname",
    how="outer"
)

firewall_features = firewall_features.merge(
    firewall_received,
    on="hostname",
    how="outer"
)


# ============================================================
# 4. ENDPOINT SECURITY FEATURES
# ============================================================

print("Creating endpoint security features...")


# ------------------------------------------------------------
# Total endpoint alerts
# ------------------------------------------------------------

endpoint_total = (
    endpoint.groupby("user_id")
    .size()
    .reset_index(name="total_endpoint_alerts")
)


# ------------------------------------------------------------
# Critical alerts
# ------------------------------------------------------------

if "severity" in endpoint.columns:

    endpoint_critical = (
        endpoint[
            endpoint["severity"].str.lower()
            == "critical"
        ]
        .groupby("user_id")
        .size()
        .reset_index(
            name="critical_endpoint_alerts"
        )
    )

else:

    endpoint_critical = pd.DataFrame(
        columns=[
            "user_id",
            "critical_endpoint_alerts"
        ]
    )


# ------------------------------------------------------------
# High severity alerts
# ------------------------------------------------------------

if "severity" in endpoint.columns:

    endpoint_high = (
        endpoint[
            endpoint["severity"].str.lower()
            == "high"
        ]
        .groupby("user_id")
        .size()
        .reset_index(
            name="high_endpoint_alerts"
        )
    )

else:

    endpoint_high = pd.DataFrame(
        columns=[
            "user_id",
            "high_endpoint_alerts"
        ]
    )


# ------------------------------------------------------------
# Endpoint alerts by hostname
# ------------------------------------------------------------

endpoint_host = (
    endpoint.groupby("hostname")
    .size()
    .reset_index(
        name="hostname_endpoint_alerts"
    )
)


# ------------------------------------------------------------
# Impossible resolution timestamps
# ------------------------------------------------------------

if "invalid_resolution_time" in endpoint.columns:

    endpoint_invalid = (
        endpoint[
            endpoint["invalid_resolution_time"] == True
        ]
        .groupby("user_id")
        .size()
        .reset_index(
            name="invalid_resolution_alerts"
        )
    )

else:

    endpoint_invalid = pd.DataFrame(
        columns=[
            "user_id",
            "invalid_resolution_alerts"
        ]
    )


# ------------------------------------------------------------
# Combine endpoint features
# ------------------------------------------------------------

endpoint_features = endpoint_total.merge(
    endpoint_critical,
    on="user_id",
    how="outer"
)

endpoint_features = endpoint_features.merge(
    endpoint_high,
    on="user_id",
    how="outer"
)

endpoint_features = endpoint_features.merge(
    endpoint_invalid,
    on="user_id",
    how="outer"
)


# ============================================================
# 5. MAP FIREWALL FEATURES TO USERS
# ============================================================

print("\nMapping firewall activity to users...")


# Firewall is connected to users through hostname
firewall_user_features = user_profile[
    [
        "user_id",
        "hostname"
    ]
].merge(
    firewall_features,
    on="hostname",
    how="left"
)


# Remove hostname after mapping
firewall_user_features = firewall_user_features.drop(
    columns=["hostname"]
)


# ============================================================
# 6. MAP ENDPOINT HOST FEATURES TO USERS
# ============================================================

print("Mapping endpoint host activity to users...")


endpoint_host_user_features = user_profile[
    [
        "user_id",
        "hostname"
    ]
].merge(
    endpoint_host,
    on="hostname",
    how="left"
)


endpoint_host_user_features = (
    endpoint_host_user_features
    .drop(columns=["hostname"])
)


# ============================================================
# 7. BUILD MASTER SECURITY DATASET
# ============================================================

print("\nBuilding unified security dataset...")


security = user_profile.copy()


# ------------------------------------------------------------
# Merge IAM
# ------------------------------------------------------------

security = security.merge(
    iam_features,
    on="user_id",
    how="left"
)


# ------------------------------------------------------------
# Merge firewall
# ------------------------------------------------------------

security = security.merge(
    firewall_user_features,
    on="user_id",
    how="left"
)


# ------------------------------------------------------------
# Merge endpoint
# ------------------------------------------------------------

security = security.merge(
    endpoint_features,
    on="user_id",
    how="left"
)


# ------------------------------------------------------------
# Merge endpoint hostname activity
# ------------------------------------------------------------

security = security.merge(
    endpoint_host_user_features,
    on="user_id",
    how="left"
)


# ============================================================
# 8. FILL SECURITY COUNTS
# ============================================================

count_columns = [
    "failed_login_count",
    "successful_login_count",
    "mfa_failure_count",
    "total_iam_events",
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


for column in count_columns:

    if column in security.columns:

        security[column] = (
            pd.to_numeric(
                security[column],
                errors="coerce"
            )
            .fillna(0)
        )


# Risk values
for column in [
    "average_iam_risk",
    "maximum_iam_risk"
]:

    if column in security.columns:

        security[column] = (
            pd.to_numeric(
                security[column],
                errors="coerce"
            )
            .fillna(0)
        )


# ============================================================
# 9. CALCULATE ZERO-TRUST SECURITY FEATURES
# ============================================================

print("\nCalculating Zero-Trust security indicators...")


# ------------------------------------------------------------
# Authentication risk
# ------------------------------------------------------------

security["authentication_risk"] = (
    security["failed_login_count"] * 5
    +
    security["mfa_failure_count"] * 7
)


# ------------------------------------------------------------
# Network risk
# ------------------------------------------------------------

security["network_risk"] = (
    security["firewall_deny_count"] * 3
    +
    security["firewall_threat_count"] * 10
)


# ------------------------------------------------------------
# Endpoint risk
# ------------------------------------------------------------

security["endpoint_risk"] = (
    security["critical_endpoint_alerts"] * 15
    +
    security["high_endpoint_alerts"] * 8
    +
    security["total_endpoint_alerts"] * 2
)


# ------------------------------------------------------------
# IAM risk contribution
# ------------------------------------------------------------

security["iam_risk_contribution"] = (
    security["average_iam_risk"] * 0.5
)


# ============================================================
# 10. PRELIMINARY ZERO-TRUST RISK SCORE
# ============================================================

security["zero_trust_risk_score"] = (

    security["authentication_risk"]

    +

    security["network_risk"]

    +

    security["endpoint_risk"]

    +

    security["iam_risk_contribution"]
)


# Limit to 0-100
security["zero_trust_risk_score"] = (
    security["zero_trust_risk_score"]
    .clip(0, 100)
    .round(2)
)


# ============================================================
# 11. RISK LEVEL
# ============================================================

def get_risk_level(score):

    if score >= 80:
        return "CRITICAL"

    if score >= 60:
        return "HIGH"

    if score >= 30:
        return "MEDIUM"

    return "LOW"


security["risk_level"] = (
    security["zero_trust_risk_score"]
    .apply(get_risk_level)
)


# ============================================================
# 12. ZERO-TRUST RECOMMENDED ACTION
# ============================================================

def get_action(level):

    if level == "CRITICAL":
        return "BLOCK"

    if level == "HIGH":
        return "RESTRICT"

    if level == "MEDIUM":
        return "VERIFY"

    return "ALLOW"


security["zero_trust_action"] = (
    security["risk_level"]
    .apply(get_action)
)


# ============================================================
# 13. INSIDER THREAT INDICATOR
# ============================================================

security["insider_threat_indicator"] = (

    (
        security["failed_login_count"] >= 3
    )

    &

    (
        security["total_endpoint_alerts"] >= 1
    )

)


# Convert True/False to 1/0
security["insider_threat_indicator"] = (
    security["insider_threat_indicator"]
    .astype(int)
)


# ============================================================
# 14. SAVE UNIFIED DATASET
# ============================================================

output_file = (
    OUTPUT_DIR
    / "unified_security_dataset.csv"
)


security.to_csv(
    output_file,
    index=False
)


# ============================================================
# 15. DISPLAY RESULTS
# ============================================================

print("\n" + "=" * 70)
print("SECURITY CORRELATION SUMMARY")
print("=" * 70)


print("\nTotal security profiles:")
print(len(security))


print("\nRisk levels:")

print(
    security["risk_level"]
    .value_counts()
)


print("\nZero-Trust actions:")

print(
    security["zero_trust_action"]
    .value_counts()
)


print("\nPotential insider threats:")

print(
    security["insider_threat_indicator"]
    .value_counts()
)


# ============================================================
# TOP 20 RISKY USERS
# ============================================================

print("\n" + "=" * 70)
print("TOP 20 HIGHEST-RISK USERS")
print("=" * 70)


top_risky = security.sort_values(
    "zero_trust_risk_score",
    ascending=False
)


display_columns = [
    "user_id",
    "username",
    "department",
    "role",
    "failed_login_count",
    "mfa_failure_count",
    "firewall_deny_count",
    "firewall_threat_count",
    "total_endpoint_alerts",
    "critical_endpoint_alerts",
    "average_iam_risk",
    "zero_trust_risk_score",
    "risk_level",
    "zero_trust_action",
    "insider_threat_indicator"
]


display_columns = [
    column
    for column in display_columns
    if column in top_risky.columns
]


print(
    top_risky[
        display_columns
    ].head(20).to_string(index=False)
)


# ============================================================
# FINAL OUTPUT
# ============================================================

print("\n" + "=" * 70)
print("UNIFIED SECURITY DATASET CREATED")
print("=" * 70)

print(output_file)

print("\nNext stage:")
print("ZERO-TRUST THREAT DETECTION")

print("=" * 70)