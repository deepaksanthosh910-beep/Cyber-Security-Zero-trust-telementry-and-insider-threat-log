from pathlib import Path
import pandas as pd
import json
import re
import ipaddress


# ============================================================
# PROJECT PATHS
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
OUTPUT_DIR = BASE_DIR / "output"

OUTPUT_DIR.mkdir(exist_ok=True)


print("=" * 70)
print("ZERO-TRUST TELEMETRY CLEANING")
print("=" * 70)


# ============================================================
# HELPER FUNCTIONS
# ============================================================

def clean_user_id(value):
    """
    Standardize employee IDs.

    Examples:
        EMP12345
        emp12345
        EMP-12345
        EMP 12345
        emp_12345
        12345

    Become:
        EMP12345
    """

    if pd.isna(value):
        return pd.NA

    value = str(value).strip().upper()

    # Keep only digits
    digits = re.sub(r"[^0-9]", "", value)

    if not digits:
        return pd.NA

    return "EMP" + digits


# ------------------------------------------------------------

def clean_department(value):
    """
    Standardize department names.
    """

    if pd.isna(value):
        return "Unknown"

    value = str(value).strip().lower()

    value = re.sub(r"\s+", " ", value)

    department_map = {

        # Operations
        "ops": "Operations",
        "ops team": "Operations",
        "operations": "Operations",
        "operation": "Operations",
        "operations dept": "Operations",
        "operations department": "Operations",

        # Legal
        "legal": "Legal",
        "legal dept": "Legal",
        "legal department": "Legal",

        # Sales
        "sales": "Sales",
        "sales team": "Sales",
        "sales dept": "Sales",
        "business sales": "Sales",

        # Human Resources
        "hr": "Human Resources",
        "hr dept": "Human Resources",
        "human resource": "Human Resources",
        "human resources": "Human Resources",
        "people team": "Human Resources",

        # Compliance
        "compliance": "Compliance",
        "compliance team": "Compliance",
        "compliance dept": "Compliance",

        # Finance
        "finance": "Finance",
        "finance team": "Finance",
        "finance dept": "Finance",
        "fin": "Finance",

        # IT
        "it": "IT",
        "it team": "IT",
        "it dept": "IT",
        "it department": "IT",
        "information technology": "IT",
        "information tech": "IT",

        # IT Support
        "it support": "IT Support",

        # Marketing
        "marketing": "Marketing",
        "marketing team": "Marketing",
        "marketing dept": "Marketing",
        "mktg": "Marketing",

        # Engineering
        "engineering": "Engineering",
        "engineering team": "Engineering",
        "engineering dept": "Engineering",

        # Customer Support
        "customer support": "Customer Support",
        "customer support team": "Customer Support",
        "customer care": "Customer Support",
        "support": "Customer Support",
        "cs": "Customer Support",

        # Procurement
        "procurement": "Procurement",
        "procurement team": "Procurement",
        "purchase": "Procurement",
        "purch": "Procurement",

        # Research and Development
        "research and development": "Research and Development",
        "research & development": "Research and Development",
        "r&d": "Research and Development",
        "rd": "Research and Development",
        "rnd": "Research and Development",

        # Accounts
        "accounts": "Accounts",
        "accounts team": "Accounts",

        # Supply Chain
        "supply chain": "Supply Chain",
        "supply chain team": "Supply Chain",

        # Call Center
        "call center": "Call Center",
        "call centre": "Call Center",

        # Innovation
        "innovation": "Innovation",

        # Brand
        "brand": "Brand",
        "brand team": "Brand"
    }

    return department_map.get(value, value.title())


# ------------------------------------------------------------

def clean_timestamp(value):
    """
    Convert different timestamp formats into
    standard pandas datetime.
    """

    if pd.isna(value):
        return pd.NaT

    value = str(value).strip()

    if value == "":
        return pd.NaT

    # Unix timestamp
    if re.fullmatch(r"\d{9,11}", value):

        try:
            number = int(value)

            return pd.to_datetime(
                number,
                unit="s",
                errors="coerce"
            )

        except Exception:
            return pd.NaT

    # Normal timestamp parsing
    return pd.to_datetime(
        value,
        errors="coerce",
        dayfirst=False
    )


# ------------------------------------------------------------

def clean_ip(value):
    """
    Validate and normalize IP addresses.

    Invalid IPs become NA.
    """

    if pd.isna(value):
        return pd.NA

    value = str(value).strip()

    if value == "":
        return pd.NA

    # Convert hyphenated IPs to dotted format
    value = value.replace("-", ".")

    try:

        ip = ipaddress.ip_address(value)

        return str(ip)

    except ValueError:

        return pd.NA


# ------------------------------------------------------------

def clean_port(value):
    """
    Convert port to numeric.
    Valid range: 0-65535.
    Invalid ports become NA.
    """

    if pd.isna(value):
        return pd.NA

    try:

        # Handle values such as "443/tcp"
        value = str(value).strip()

        number_match = re.search(r"\d+", value)

        if not number_match:
            return pd.NA

        port = int(number_match.group())

        if 0 <= port <= 65535:
            return port

        return pd.NA

    except Exception:

        return pd.NA


# ------------------------------------------------------------

def clean_bytes(value):
    """
    Convert byte values to numeric.
    """

    if pd.isna(value):
        return 0

    try:

        value = str(value).strip()

        number_match = re.search(r"-?\d+(?:\.\d+)?", value)

        if not number_match:
            return 0

        number = float(number_match.group())

        if number < 0:
            return 0

        return int(number)

    except Exception:

        return 0


# ------------------------------------------------------------

def clean_risk_score(value):
    """
    Convert IAM risk scores into a numeric 0-100 range.

    Examples:
        80
        "80"
        "80/100"
        "HIGH"
        "Medium"

    Invalid values become 0.
    """

    if pd.isna(value):
        return 0

    value = str(value).strip().lower()

    # Numeric value
    number_match = re.search(r"\d+(?:\.\d+)?", value)

    if number_match:

        try:

            score = float(number_match.group())

            # Clamp to 0-100
            score = max(0, min(100, score))

            return score

        except Exception:
            pass

    # Text risk levels
    if value == "critical":
        return 100

    if value == "high":
        return 80

    if value == "medium":
        return 50

    if value == "low":
        return 20

    return 0


# ------------------------------------------------------------

def clean_mfa(value):
    """
    Convert MFA values into:
        1 = passed
        0 = failed
    """

    if pd.isna(value):
        return 0

    value = str(value).strip().lower()

    passed_values = {
        "true",
        "1",
        "yes",
        "y",
        "passed",
        "pass",
        "success"
    }

    failed_values = {
        "false",
        "0",
        "no",
        "n",
        "failed",
        "fail"
    }

    if value in passed_values:
        return 1

    if value in failed_values:
        return 0

    return 0


# ------------------------------------------------------------

def clean_event_type(value):
    """
    Normalize IAM event types.

    Required project categories:
        login_success
        login_failed
        other
    """

    if pd.isna(value):
        return "other"

    value = str(value).strip().lower()

    # Remove spaces and hyphens
    normalized = value.replace("-", "_")
    normalized = normalized.replace(" ", "_")

    success_events = {
        "login_success",
        "logon_success",
        "auth_success",
        "success_login",
        "sso_success",
        "successful_login"
    }

    failed_events = {
        "login_failed",
        "login_failure",
        "logon_failure",
        "auth_failed",
        "failed_login",
        "failed_logon",
        "invalid_credentials"
    }

    if normalized in success_events:
        return "login_success"

    if normalized in failed_events:
        return "login_failed"

    # MFA failures are authentication failures
    if "mfa" in normalized and "fail" in normalized:
        return "login_failed"

    if "failed" in normalized or "failure" in normalized:
        return "login_failed"

    return "other"


# ------------------------------------------------------------

def clean_protocol(value):

    if pd.isna(value):
        return "UNKNOWN"

    value = str(value).strip().upper()

    if value == "":
        return "UNKNOWN"

    return value


# ------------------------------------------------------------

def clean_action(value):

    if pd.isna(value):
        return "UNKNOWN"

    value = str(value).strip().lower()

    if value in {"allow", "allowed", "accept", "accepted", "permit"}:
        return "ALLOW"

    if value in {"deny", "denied", "block", "blocked", "drop"}:
        return "DENY"

    return value.upper()


# ------------------------------------------------------------

def clean_threat_flag(value):

    if pd.isna(value):
        return 0

    value = str(value).strip().lower()

    if value in {
        "true",
        "1",
        "yes",
        "y",
        "threat",
        "malicious"
    }:
        return 1

    return 0


# ------------------------------------------------------------

def clean_severity(value):

    if pd.isna(value):
        return "Unknown"

    value = str(value).strip().lower()

    if value in {"critical", "crit"}:
        return "Critical"

    if value in {"high", "hi"}:
        return "High"

    if value in {"medium", "med", "moderate"}:
        return "Medium"

    if value in {"low", "lo"}:
        return "Low"

    return value.title()


# ------------------------------------------------------------

def clean_status(value):

    if pd.isna(value):
        return "Unknown"

    value = str(value).strip().lower()

    if value in {"open", "opened", "active"}:
        return "Open"

    if value in {"closed", "resolved", "fixed"}:
        return "Resolved"

    if value in {"in progress", "investigating", "processing"}:
        return "In Progress"

    return value.title()


# ============================================================
# 1. LOAD IAM
# ============================================================

print("\n[1/4] Loading IAM audit trail...")

iam_file = DATA_DIR / "track2_iam_audit_trail.json"

with open(iam_file, "r", encoding="utf-8") as f:

    iam_data = json.load(f)

iam = pd.DataFrame(iam_data)

print("IAM records:", len(iam))


# ============================================================
# CLEAN IAM
# ============================================================

print("\nCleaning IAM telemetry...")

if "user_id" in iam.columns:
    iam["user_id"] = iam["user_id"].apply(clean_user_id)

if "department" in iam.columns:
    iam["department"] = iam["department"].apply(clean_department)

if "timestamp" in iam.columns:
    iam["timestamp"] = iam["timestamp"].apply(clean_timestamp)

if "event_type" in iam.columns:
    iam["event_type"] = iam["event_type"].apply(clean_event_type)

if "source_ip" in iam.columns:
    iam["source_ip"] = iam["source_ip"].apply(clean_ip)

if "risk_score" in iam.columns:
    iam["risk_score"] = iam["risk_score"].apply(clean_risk_score)

if "mfa_passed" in iam.columns:
    iam["mfa_passed"] = iam["mfa_passed"].apply(clean_mfa)

if "username" in iam.columns:
    iam["username"] = (
        iam["username"]
        .astype("string")
        .str.strip()
        .str.lower()
    )

if "hostname" in iam.columns:
    iam["hostname"] = (
        iam["hostname"]
        .astype("string")
        .str.strip()
        .str.upper()
        .str.replace("_", "-", regex=False)
    )

if "device_id" in iam.columns:
    iam["device_id"] = (
        iam["device_id"]
        .astype("string")
        .str.strip()
        .str.upper()
    )

if "session_id" in iam.columns:
    iam["session_id"] = (
        iam["session_id"]
        .astype("string")
        .str.strip()
        .str.upper()
        .str.replace("-", "", regex=False)
    )


iam = iam.drop_duplicates()


print("IAM cleaning complete.")


# ============================================================
# 2. LOAD FIREWALL
# ============================================================

print("\n[2/4] Loading firewall logs...")

firewall_file = DATA_DIR / "track2_firewall_logs.csv"

firewall = pd.read_csv(firewall_file)

print("Firewall records:", len(firewall))


# ============================================================
# CLEAN FIREWALL
# ============================================================

print("\nCleaning firewall telemetry...")

if "timestamp" in firewall.columns:
    firewall["timestamp"] = firewall["timestamp"].apply(
        clean_timestamp
    )

if "hostname" in firewall.columns:
    firewall["hostname"] = (
        firewall["hostname"]
        .astype("string")
        .str.strip()
        .str.upper()
        .str.replace("_", "-", regex=False)
    )

for column in ["src_ip", "dst_ip"]:

    if column in firewall.columns:
        firewall[column] = firewall[column].apply(clean_ip)


for column in ["src_port", "dst_port"]:

    if column in firewall.columns:
        firewall[column] = firewall[column].apply(clean_port)


if "protocol" in firewall.columns:
    firewall["protocol"] = firewall["protocol"].apply(
        clean_protocol
    )


if "action" in firewall.columns:
    firewall["action"] = firewall["action"].apply(
        clean_action
    )


for column in ["bytes_sent", "bytes_received"]:

    if column in firewall.columns:
        firewall[column] = firewall[column].apply(
            clean_bytes
        )


if "threat_flag" in firewall.columns:
    firewall["threat_flag"] = firewall["threat_flag"].apply(
        clean_threat_flag
    )


if "session_id" in firewall.columns:
    firewall["session_id"] = (
        firewall["session_id"]
        .astype("string")
        .str.strip()
        .str.upper()
        .str.replace("-", "", regex=False)
    )


firewall = firewall.drop_duplicates()


print("Firewall cleaning complete.")


# ============================================================
# 3. LOAD ENDPOINT
# ============================================================

print("\n[3/4] Loading endpoint alerts...")

endpoint_file = DATA_DIR / "track2_endpoint_alerts.xlsx"

endpoint = pd.read_excel(endpoint_file)

print("Endpoint records:", len(endpoint))


# ============================================================
# CLEAN ENDPOINT
# ============================================================

print("\nCleaning endpoint telemetry...")

if "detected_timestamp" in endpoint.columns:

    endpoint["detected_timestamp"] = endpoint[
        "detected_timestamp"
    ].apply(clean_timestamp)


if "resolved_timestamp" in endpoint.columns:

    endpoint["resolved_timestamp"] = endpoint[
        "resolved_timestamp"
    ].apply(clean_timestamp)


if "user_id" in endpoint.columns:

    endpoint["user_id"] = endpoint[
        "user_id"
    ].apply(clean_user_id)


if "hostname" in endpoint.columns:

    endpoint["hostname"] = (
        endpoint["hostname"]
        .astype("string")
        .str.strip()
        .str.upper()
        .str.replace("_", "-", regex=False)
    )


if "severity" in endpoint.columns:

    endpoint["severity"] = endpoint[
        "severity"
    ].apply(clean_severity)


if "status" in endpoint.columns:

    endpoint["status"] = endpoint[
        "status"
    ].apply(clean_status)


if "sha256" in endpoint.columns:

    endpoint["sha256"] = (
        endpoint["sha256"]
        .astype("string")
        .str.strip()
        .str.lower()
    )


endpoint = endpoint.drop_duplicates()


# ------------------------------------------------------------
# Detect impossible resolution timestamps
# ------------------------------------------------------------

if (
    "detected_timestamp" in endpoint.columns
    and "resolved_timestamp" in endpoint.columns
):

    endpoint["invalid_resolution_time"] = (
        endpoint["resolved_timestamp"]
        < endpoint["detected_timestamp"]
    )

else:

    endpoint["invalid_resolution_time"] = False


print("Endpoint cleaning complete.")


# ============================================================
# 4. LOAD IDENTITY MASTER
# ============================================================

print("\n[4/4] Loading identity asset master...")

identity_file = DATA_DIR / "track2_identity_asset_master.csv"

identity = pd.read_csv(identity_file)

print("Identity records:", len(identity))


# ============================================================
# CLEAN IDENTITY
# ============================================================

print("\nCleaning identity/asset master...")

if "user_id" in identity.columns:

    identity["user_id"] = identity[
        "user_id"
    ].apply(clean_user_id)


if "department" in identity.columns:

    identity["department"] = identity[
        "department"
    ].apply(clean_department)


if "username" in identity.columns:

    identity["username"] = (
        identity["username"]
        .astype("string")
        .str.strip()
        .str.lower()
    )


if "hostname" in identity.columns:

    identity["hostname"] = (
        identity["hostname"]
        .astype("string")
        .str.strip()
        .str.upper()
        .str.replace("_", "-", regex=False)
    )


if "device_id" in identity.columns:

    identity["device_id"] = (
        identity["device_id"]
        .astype("string")
        .str.strip()
        .str.upper()
    )


if "status" in identity.columns:

    identity["status"] = (
        identity["status"]
        .astype("string")
        .str.strip()
        .str.title()
    )


identity = identity.drop_duplicates()


print("Identity cleaning complete.")


# ============================================================
# SAVE CLEANED FILES
# ============================================================

print("\nSaving cleaned telemetry...")


iam_output = OUTPUT_DIR / "cleaned_iam.csv"
firewall_output = OUTPUT_DIR / "cleaned_firewall.csv"
endpoint_output = OUTPUT_DIR / "cleaned_endpoint.csv"
identity_output = OUTPUT_DIR / "cleaned_identity.csv"


iam.to_csv(iam_output, index=False)
firewall.to_csv(firewall_output, index=False)
endpoint.to_csv(endpoint_output, index=False)
identity.to_csv(identity_output, index=False)


# ============================================================
# FINAL DATA QUALITY REPORT
# ============================================================

print("\n" + "=" * 70)
print("DATA CLEANING SUMMARY")
print("=" * 70)


print("\nIAM")
print("-" * 40)
print("Records:", len(iam))
print("Unique users:", iam["user_id"].nunique())

if "event_type" in iam.columns:
    print("\nEvent types:")
    print(iam["event_type"].value_counts())

if "department" in iam.columns:
    print("\nDepartments:")
    print(iam["department"].value_counts().head(15))

if "risk_score" in iam.columns:
    print(
        "\nAverage risk score:",
        round(iam["risk_score"].mean(), 2)
    )


print("\nFIREWALL")
print("-" * 40)
print("Records:", len(firewall))

if "action" in firewall.columns:
    print("\nActions:")
    print(firewall["action"].value_counts())

if "protocol" in firewall.columns:
    print("\nProtocols:")
    print(firewall["protocol"].value_counts())

if "threat_flag" in firewall.columns:
    print(
        "\nThreat flags:",
        firewall["threat_flag"].sum()
    )


print("\nENDPOINT")
print("-" * 40)
print("Records:", len(endpoint))

if "severity" in endpoint.columns:
    print("\nSeverity:")
    print(endpoint["severity"].value_counts())

if "status" in endpoint.columns:
    print("\nStatus:")
    print(endpoint["status"].value_counts())

if "invalid_resolution_time" in endpoint.columns:
    print(
        "\nImpossible resolution timestamps:",
        endpoint["invalid_resolution_time"].sum()
    )


print("\nIDENTITY")
print("-" * 40)
print("Records:", len(identity))

if "department" in identity.columns:
    print(
        "Departments:",
        identity["department"].nunique()
    )

if "user_id" in identity.columns:
    print(
        "Unique users:",
        identity["user_id"].nunique()
    )


# ============================================================
# OUTPUT FILES
# ============================================================

print("\n" + "=" * 70)
print("CLEANED FILES CREATED")
print("=" * 70)

print(iam_output)
print(firewall_output)
print(endpoint_output)
print(identity_output)


print("\n" + "=" * 70)
print("ZERO-TRUST TELEMETRY CLEANING COMPLETE")
print("=" * 70)