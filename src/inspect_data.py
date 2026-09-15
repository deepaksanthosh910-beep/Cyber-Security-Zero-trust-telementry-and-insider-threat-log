from pathlib import Path
import pandas as pd
import json

# Find the data folder
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"

print("=" * 60)
print("CYBERSECURITY DATASET INSPECTION")
print("=" * 60)


# 1. Firewall Logs
print("\n\n🔥 FIREWALL LOGS")
print("-" * 60)

firewall_file = DATA_DIR / "track2_firewall_logs.csv"

if firewall_file.exists():
    firewall = pd.read_csv(firewall_file)

    print("Rows:", len(firewall))
    print("Columns:", len(firewall.columns))
    print("\nColumn names:")
    print(list(firewall.columns))

    print("\nMissing values:")
    print(firewall.isnull().sum())

    print("\nFirst 5 rows:")
    print(firewall.head())
else:
    print("File not found:", firewall_file)


# 2. IAM Audit Trail
print("\n\n🔐 IAM AUDIT TRAIL")
print("-" * 60)

iam_file = DATA_DIR / "track2_iam_audit_trail.json"

if iam_file.exists():
    with open(iam_file, "r", encoding="utf-8") as f:
        iam_data = json.load(f)

    iam = pd.DataFrame(iam_data)

    print("Rows:", len(iam))
    print("Columns:", len(iam.columns))
    print("\nColumn names:")
    print(list(iam.columns))

    print("\nMissing values:")
    print(iam.isnull().sum())

    print("\nFirst 5 rows:")
    print(iam.head())
else:
    print("File not found:", iam_file)


# 3. Endpoint Alerts
print("\n\n🚨 ENDPOINT ALERTS")
print("-" * 60)

endpoint_file = DATA_DIR / "track2_endpoint_alerts.xlsx"

if endpoint_file.exists():
    endpoint = pd.read_excel(endpoint_file)

    print("Rows:", len(endpoint))
    print("Columns:", len(endpoint.columns))
    print("\nColumn names:")
    print(list(endpoint.columns))

    print("\nMissing values:")
    print(endpoint.isnull().sum())

    print("\nFirst 5 rows:")
    print(endpoint.head())
else:
    print("File not found:", endpoint_file)


# 4. Identity Asset Master
print("\n\n👤 IDENTITY ASSET MASTER")
print("-" * 60)

identity_file = DATA_DIR / "track2_identity_asset_master.csv"

if identity_file.exists():
    identity = pd.read_csv(identity_file)

    print("Rows:", len(identity))
    print("Columns:", len(identity.columns))
    print("\nColumn names:")
    print(list(identity.columns))

    print("\nMissing values:")
    print(identity.isnull().sum())

    print("\nFirst 5 rows:")
    print(identity.head())
else:
    print("File not found:", identity_file)


print("\n\n" + "=" * 60)
print("INSPECTION COMPLETE")
print("=" * 60)