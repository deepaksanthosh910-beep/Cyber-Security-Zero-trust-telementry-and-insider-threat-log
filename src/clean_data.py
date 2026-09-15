from pathlib import Path
import pandas as pd
import json
import re


# ============================================
# PROJECT PATHS
# ============================================

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
OUTPUT_DIR = BASE_DIR / "output"

OUTPUT_DIR.mkdir(exist_ok=True)


# ============================================
# USER ID CLEANING
# ============================================

def clean_user_id(value):

    if pd.isna(value):
        return pd.NA

    value = str(value).strip().upper()

    # Remove EMP prefix
    value = re.sub(r"^EMP", "", value)

    # Keep only numbers
    value = re.sub(r"[^0-9]", "", value)

    # Empty value
    if not value:
        return pd.NA

    return "EMP" + value


# ============================================
# DEPARTMENT CLEANING
# ============================================

def clean_department(value):

    if pd.isna(value):
        return "Unknown"

    value = str(value).strip().lower()

    # Remove extra spaces
    value = re.sub(r"\s+", " ", value)

    department_map = {

        # ------------------------------------
        # OPERATIONS
        # ------------------------------------
        "ops": "Operations",
        "ops team": "Operations",
        "operations": "Operations",
        "operation": "Operations",
        "operations dept": "Operations",
        "operations department": "Operations",

        # ------------------------------------
        # LEGAL
        # ------------------------------------
        "legal": "Legal",
        "legal dept": "Legal",
        "legal department": "Legal",

        # ------------------------------------
        # SALES
        # ------------------------------------
        "sales": "Sales",
        "sales team": "Sales",
        "sales dept": "Sales",

        # ------------------------------------
        # HUMAN RESOURCES
        # ------------------------------------
        "human resource": "Human Resources",
        "human resources": "Human Resources",
        "hr": "Human Resources",
        "hr dept": "Human Resources",

        # People Team
        "people team": "Human Resources",

        # ------------------------------------
        # COMPLIANCE
        # ------------------------------------
        "compliance": "Compliance",
        "compliance team": "Compliance",
        "compliance dept": "Compliance",

        # ------------------------------------
        # FINANCE
        # ------------------------------------
        "finance": "Finance",
        "finance team": "Finance",
        "finance dept": "Finance",
        "fin": "Finance",

        # ------------------------------------
        # INFORMATION TECHNOLOGY
        # ------------------------------------
        "it": "IT",
        "it team": "IT",
        "it dept": "IT",
        "it department": "IT",
        "information technology": "IT",
        "information tech": "IT",

        # ------------------------------------
        # IT SUPPORT
        # ------------------------------------
        "it support": "IT Support",

        # ------------------------------------
        # MARKETING
        # ------------------------------------
        "marketing": "Marketing",
        "marketing team": "Marketing",
        "marketing dept": "Marketing",
        "mktg": "Marketing",

        # ------------------------------------
        # ENGINEERING
        # ------------------------------------
        "engineering": "Engineering",
        "engineering team": "Engineering",
        "engineering dept": "Engineering",

        # ------------------------------------
        # CUSTOMER SUPPORT
        # ------------------------------------
        "customer support": "Customer Support",
        "customer support team": "Customer Support",
        "customer care": "Customer Support",

        # ------------------------------------
        # PROCUREMENT
        # ------------------------------------
        "procurement": "Procurement",
        "procurement team": "Procurement",

        # Purchase
        "purchase": "Procurement",

        # ------------------------------------
        # RESEARCH & DEVELOPMENT
        # ------------------------------------
        "research and development": "Research and Development",
        "research & development": "Research and Development",
        "r&d": "Research and Development",
        "rd": "Research and Development",
        "rnd": "Research and Development",

        # ------------------------------------
        # ACCOUNTS
        # ------------------------------------
        "accounts": "Accounts",
        "accounts team": "Accounts",

        # ------------------------------------
        # SUPPLY CHAIN
        # ------------------------------------
        "supply chain": "Supply Chain",
        "supply chain team": "Supply Chain",

        # ------------------------------------
        # CALL CENTER
        # ------------------------------------
        "call center": "Call Center",
        "call centre": "Call Center",

        # ------------------------------------
        # INNOVATION
        # ------------------------------------
        "innovation": "Innovation",

        # ------------------------------------
        # BRAND
        # ------------------------------------
        "brand team": "Brand",
        "brand": "Brand",

        # ------------------------------------
        # BUSINESS SALES
        # ------------------------------------
        "business sales": "Sales"
    }

    # Return standardized department
    if value in department_map:
        return department_map[value]

    # If unknown, capitalize properly
    return value.title()


# ============================================
# START
# ============================================

print("=" * 60)
print("STARTING DATA CLEANING")
print("=" * 60)


# ============================================
# LOAD IAM DATA
# ============================================

iam_file = DATA_DIR / "track2_iam_audit_trail.json"

print("\nLoading IAM audit trail...")

try:

    with open(iam_file, "r", encoding="utf-8") as f:
        iam_data = json.load(f)

    iam = pd.DataFrame(iam_data)

    print("IAM records loaded:", len(iam))

except FileNotFoundError:

    print("ERROR: IAM file not found:")
    print(iam_file)
    raise

except Exception as e:

    print("ERROR loading IAM file:")
    print(e)
    raise


# ============================================
# CLEAN IAM USER ID
# ============================================

if "user_id" in iam.columns:

    iam["user_id"] = iam["user_id"].apply(clean_user_id)

    print("IAM user IDs cleaned.")

else:

    print("WARNING: user_id column not found in IAM data.")


# ============================================
# CLEAN IAM DEPARTMENT
# ============================================

if "department" in iam.columns:

    iam["department"] = iam["department"].apply(clean_department)

    print("IAM departments cleaned.")

else:

    print("WARNING: department column not found in IAM data.")


# ============================================
# LOAD IDENTITY MASTER
# ============================================

identity_file = DATA_DIR / "track2_identity_asset_master.csv"

print("\nLoading identity asset master...")

try:

    identity = pd.read_csv(identity_file)

    print("Identity records loaded:", len(identity))

except FileNotFoundError:

    print("ERROR: Identity master file not found:")
    print(identity_file)
    raise

except Exception as e:

    print("ERROR loading identity master:")
    print(e)
    raise


# ============================================
# CLEAN IDENTITY USER ID
# ============================================

if "user_id" in identity.columns:

    identity["user_id"] = identity["user_id"].apply(clean_user_id)

    print("Identity user IDs cleaned.")

else:

    print("WARNING: user_id column not found in identity master.")


# ============================================
# CLEAN IDENTITY DEPARTMENT
# ============================================

if "department" in identity.columns:

    identity["department"] = identity["department"].apply(clean_department)

    print("Identity departments cleaned.")

else:

    print("WARNING: department column not found in identity master.")


# ============================================
# REMOVE DUPLICATES
# ============================================

print("\nChecking duplicates...")

iam_duplicates = iam.duplicated().sum()
identity_duplicates = identity.duplicated().sum()

print("IAM duplicate rows:", iam_duplicates)
print("Identity duplicate rows:", identity_duplicates)

if iam_duplicates > 0:

    iam = iam.drop_duplicates()

    print("IAM duplicates removed.")

if identity_duplicates > 0:

    identity = identity.drop_duplicates()

    print("Identity duplicates removed.")


# ============================================
# SAVE CLEANED DATA
# ============================================

iam_output = OUTPUT_DIR / "cleaned_iam_audit.csv"
identity_output = OUTPUT_DIR / "cleaned_identity_asset_master.csv"

iam.to_csv(iam_output, index=False)
identity.to_csv(identity_output, index=False)


print("\nCleaned files saved:")
print(iam_output)
print(identity_output)


# ============================================
# IAM DEPARTMENT RESULTS
# ============================================

print("\n" + "=" * 60)
print("IAM DEPARTMENTS AFTER CLEANING")
print("=" * 60)

if "department" in iam.columns:

    print(
        iam["department"]
        .value_counts(dropna=False)
    )


# ============================================
# IDENTITY DEPARTMENT RESULTS
# ============================================

print("\n" + "=" * 60)
print("IDENTITY DEPARTMENTS AFTER CLEANING")
print("=" * 60)

if "department" in identity.columns:

    print(
        identity["department"]
        .value_counts(dropna=False)
    )


# ============================================
# ALL UNIQUE IAM DEPARTMENTS
# ============================================

print("\n" + "=" * 60)
print("ALL UNIQUE IAM DEPARTMENTS")
print("=" * 60)

if "department" in iam.columns:

    for dept in sorted(
        iam["department"]
        .dropna()
        .unique()
    ):

        print(dept)


# ============================================
# ALL UNIQUE IDENTITY DEPARTMENTS
# ============================================

print("\n" + "=" * 60)
print("ALL UNIQUE IDENTITY DEPARTMENTS")
print("=" * 60)

if "department" in identity.columns:

    for dept in sorted(
        identity["department"]
        .dropna()
        .unique()
    ):

        print(dept)


# ============================================
# FINAL SUMMARY
# ============================================

print("\n" + "=" * 60)
print("DATA CLEANING SUMMARY")
print("=" * 60)

print("IAM records:", len(iam))
print("Identity records:", len(identity))

print(
    "IAM unique users:",
    iam["user_id"].nunique()
    if "user_id" in iam.columns
    else "N/A"
)

print(
    "Identity unique users:",
    identity["user_id"].nunique()
    if "user_id" in identity.columns
    else "N/A"
)

print(
    "IAM departments:",
    iam["department"].nunique()
    if "department" in iam.columns
    else "N/A"
)

print(
    "Identity departments:",
    identity["department"].nunique()
    if "department" in identity.columns
    else "N/A"
)

print("\n" + "=" * 60)
print("DEPARTMENT CLEANING COMPLETE")
print("=" * 60)