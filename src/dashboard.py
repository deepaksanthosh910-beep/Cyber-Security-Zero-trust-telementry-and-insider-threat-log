from pathlib import Path
import pandas as pd
import streamlit as st


# ============================================================
# PAGE CONFIGURATION
# ============================================================

st.set_page_config(
    page_title="Zero-Trust Security Center",
    page_icon="🔐",
    layout="wide"
)


# ============================================================
# PROJECT PATH
# ============================================================

BASE_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = BASE_DIR / "output"

DATA_FILE = OUTPUT_DIR / "insider_threat_results.csv"


# ============================================================
# LOAD DATA
# ============================================================

@st.cache_data
def load_data():

    df = pd.read_csv(
        DATA_FILE,
        low_memory=False
    )

    return df


try:

    security = load_data()

except FileNotFoundError:

    st.error(
        "Security results file was not found."
    )

    st.info(
        "Run insider_threat_detector.py first."
    )

    st.stop()


# ============================================================
# HEADER
# ============================================================

st.title("🔐 Zero-Trust Security Center")

st.markdown(
    """
    ### AI-Assisted Insider Threat Monitoring

    Continuous security analysis of identity, authentication,
    network and endpoint telemetry.
    """
)


st.divider()


# ============================================================
# SIDEBAR
# ============================================================

st.sidebar.title("🛡️ Security Controls")

st.sidebar.markdown(
    """
    **Zero-Trust Policy**

    Every user and device is continuously evaluated
    based on security telemetry.
    """
)


# ============================================================
# SIDEBAR FILTERS
# ============================================================

st.sidebar.subheader("Filters")


# Risk filter
risk_levels = [
    "ALL",
    "CRITICAL",
    "HIGH",
    "MEDIUM",
    "LOW"
]

selected_risk = st.sidebar.selectbox(
    "Risk Level",
    risk_levels
)


# Department filter
if "department" in security.columns:

    departments = sorted(
        security["department"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    selected_department = st.sidebar.selectbox(
        "Department",
        ["ALL"] + departments
    )

else:

    selected_department = "ALL"


# Threat filter
threat_types = [
    "ALL",
    "LIKELY INSIDER THREAT",
    "SUSPICIOUS",
    "ANOMALOUS",
    "NORMAL"
]

selected_threat = st.sidebar.selectbox(
    "Threat Classification",
    threat_types
)


# ============================================================
# APPLY FILTERS
# ============================================================

filtered = security.copy()


if selected_risk != "ALL":

    filtered = filtered[
        filtered["insider_risk_level"]
        == selected_risk
    ]


if selected_department != "ALL":

    filtered = filtered[
        filtered["department"]
        == selected_department
    ]


if selected_threat != "ALL":

    filtered = filtered[
        filtered["threat_classification"]
        == selected_threat
    ]


# ============================================================
# KEY METRICS
# ============================================================

st.subheader("📊 Security Overview")


total_users = len(security)


critical_users = len(
    security[
        security["insider_risk_level"]
        == "CRITICAL"
    ]
)


high_users = len(
    security[
        security["insider_risk_level"]
        == "HIGH"
    ]
)


suspicious_users = len(
    security[
        security["threat_classification"]
        .isin(
            [
                "LIKELY INSIDER THREAT",
                "SUSPICIOUS"
            ]
        )
    ]
)


col1, col2, col3, col4 = st.columns(4)


with col1:

    st.metric(
        "👥 Total Users",
        f"{total_users:,}"
    )


with col2:

    st.metric(
        "🔴 Critical Risk",
        f"{critical_users:,}"
    )


with col3:

    st.metric(
        "🟠 High Risk",
        f"{high_users:,}"
    )


with col4:

    st.metric(
        "⚠️ Suspicious Users",
        f"{suspicious_users:,}"
    )


st.divider()


# ============================================================
# RISK DISTRIBUTION
# ============================================================

st.subheader("🎯 Risk Distribution")


risk_distribution = (
    security["insider_risk_level"]
    .value_counts()
    .reindex(
        [
            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW"
        ],
        fill_value=0
    )
)


chart_col1, chart_col2 = st.columns(2)


with chart_col1:

    st.markdown("#### Users by Risk Level")

    st.bar_chart(
        risk_distribution
    )


with chart_col2:

    st.markdown("#### Zero-Trust Actions")

    action_distribution = (
        security["recommended_action"]
        .value_counts()
    )

    st.bar_chart(
        action_distribution
    )


# ============================================================
# THREAT CLASSIFICATION
# ============================================================

st.subheader("🚨 Threat Classification")


threat_distribution = (
    security["threat_classification"]
    .value_counts()
)


st.bar_chart(
    threat_distribution
)


# ============================================================
# TOP HIGH-RISK USERS
# ============================================================

st.subheader("🔥 Highest-Risk Users")


top_users = security.sort_values(
    "insider_threat_score",
    ascending=False
).head(20)


top_columns = [
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
    "insider_threat_score",
    "insider_risk_level",
    "threat_classification",
    "recommended_action"
]


top_columns = [
    column
    for column in top_columns
    if column in top_users.columns
]


st.dataframe(
    top_users[
        top_columns
    ],
    use_container_width=True,
    hide_index=True
)


# ============================================================
# SELECT A USER
# ============================================================

st.divider()

st.subheader("🔎 Investigate a User")


if len(filtered) > 0:

    user_options = (
        filtered["user_id"]
        .dropna()
        .astype(str)
        .tolist()
    )

    selected_user = st.selectbox(
        "Select Employee",
        user_options
    )


    user_data = filtered[
        filtered["user_id"].astype(str)
        == selected_user
    ]


    if len(user_data) > 0:

        user = user_data.iloc[0]


        # ----------------------------------------------------
        # USER INFORMATION
        # ----------------------------------------------------

        st.markdown("### 👤 User Profile")


        profile_col1, profile_col2, profile_col3 = (
            st.columns(3)
        )


        with profile_col1:

            st.write(
                "**User ID:**",
                user.get("user_id", "Unknown")
            )

            st.write(
                "**Username:**",
                user.get("username", "Unknown")
            )

            st.write(
                "**Department:**",
                user.get("department", "Unknown")
            )


        with profile_col2:

            st.write(
                "**Role:**",
                user.get("role", "Unknown")
            )

            st.write(
                "**Hostname:**",
                user.get("hostname", "Unknown")
            )

            st.write(
                "**Status:**",
                user.get("status", "Unknown")
            )


        with profile_col3:

            st.metric(
                "Threat Score",
                f'{user["insider_threat_score"]:.1f}/100'
            )

            st.write(
                "**Risk Level:**",
                user["insider_risk_level"]
            )

            st.write(
                "**Zero-Trust Action:**",
                user["recommended_action"]
            )


        # ----------------------------------------------------
        # SECURITY SIGNALS
        # ----------------------------------------------------

        st.markdown("### 📡 Security Signals")


        signal_col1, signal_col2, signal_col3, signal_col4 = (
            st.columns(4)
        )


        with signal_col1:

            st.metric(
                "Failed Logins",
                int(user["failed_login_count"])
            )

            st.metric(
                "MFA Failures",
                int(user["mfa_failure_count"])
            )


        with signal_col2:

            st.metric(
                "Firewall Denies",
                int(user["firewall_deny_count"])
            )

            st.metric(
                "Firewall Threats",
                int(user["firewall_threat_count"])
            )


        with signal_col3:

            st.metric(
                "Endpoint Alerts",
                int(user["total_endpoint_alerts"])
            )

            st.metric(
                "Critical Alerts",
                int(user["critical_endpoint_alerts"])
            )


        with signal_col4:

            st.metric(
                "IAM Risk",
                f'{user["average_iam_risk"]:.1f}'
            )

            st.metric(
                "Security Signals",
                int(user["security_signal_count"])
            )


        # ----------------------------------------------------
        # THREAT EXPLANATION
        # ----------------------------------------------------

        st.markdown("### 🧠 Why Was This User Flagged?")


        explanation = user.get(
            "threat_explanation",
            "No explanation available."
        )


        if user["insider_risk_level"] == "CRITICAL":

            st.error(
                f"🚨 CRITICAL RISK\n\n{explanation}"
            )

        elif user["insider_risk_level"] == "HIGH":

            st.warning(
                f"⚠️ HIGH RISK\n\n{explanation}"
            )

        elif user["insider_risk_level"] == "MEDIUM":

            st.info(
                f"🔎 MEDIUM RISK\n\n{explanation}"
            )

        else:

            st.success(
                f"✅ LOW RISK\n\n{explanation}"
            )


        # ----------------------------------------------------
        # ZERO TRUST DECISION
        # ----------------------------------------------------

        st.markdown("### 🛡️ Zero-Trust Decision")


        action = user["recommended_action"]


        if action == "BLOCK":

            st.error(
                "🚫 BLOCK ACCESS — Immediate security investigation recommended."
            )

        elif action == "RESTRICT":

            st.warning(
                "🔒 RESTRICT ACCESS — Require additional verification."
            )

        elif action == "VERIFY":

            st.info(
                "🔐 VERIFY IDENTITY — Require additional authentication."
            )

        else:

            st.success(
                "✅ ALLOW — No significant security anomaly detected."
            )


else:

    st.warning(
        "No users match the selected filters."
    )


# ============================================================
# FOOTER
# ============================================================

st.divider()


st.markdown(
    """
    ### 🔐 Zero-Trust Security Principle

    **Never trust automatically. Always verify.**

    This system combines identity, authentication, network,
    and endpoint telemetry to continuously evaluate user risk.

    **Detection → Risk Scoring → Explanation → Zero-Trust Action**
    """
)