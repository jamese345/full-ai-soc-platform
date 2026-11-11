import sys
from pathlib import Path

# ---------------------------------------------------------
# Project import path
# ---------------------------------------------------------

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


import pandas as pd
import streamlit as st

from src.pipeline import process_alerts
from src.cases.case_manager import CaseManager


# ---------------------------------------------------------
# Page configuration
# ---------------------------------------------------------

st.set_page_config(
    page_title="AI SOC Analyst Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)


# ---------------------------------------------------------
# Styling
# ---------------------------------------------------------

st.markdown(
    """
    <style>

    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        margin-bottom: 0.2rem;
    }

    .sub-header {
        color: #777;
        margin-bottom: 1.5rem;
    }

    .section-header {
        font-size: 1.4rem;
        font-weight: 650;
        margin-top: 1rem;
        margin-bottom: 0.8rem;
    }

    </style>
    """,
    unsafe_allow_html=True,
)


# ---------------------------------------------------------
# Header
# ---------------------------------------------------------

st.markdown(
    '<div class="main-header">🛡️ AI SOC Analyst Platform</div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="sub-header">'
    'Threat Detection • ML Anomaly Detection • Threat Intelligence • '
    'MITRE ATT&CK • RAG • AI Investigation • Case Management'
    '</div>',
    unsafe_allow_html=True,
)


# ---------------------------------------------------------
# Session state
# ---------------------------------------------------------

if "case_manager" not in st.session_state:
    st.session_state["case_manager"] = CaseManager()


# ---------------------------------------------------------
# Sidebar
# ---------------------------------------------------------

with st.sidebar:

    st.header("⚙️ SOC Controls")

    alert_file = st.text_input(
        "Alert Dataset",
        value="data/alerts/sample_alerts.json",
    )

    run_ai = st.toggle(
        "Enable AI Investigation",
        value=False,
        help=(
            "Runs the AI investigation agent after "
            "deterministic investigation."
        ),
    )

    run_pipeline = st.button(
        "🚀 Run SOC Analysis",
        use_container_width=True,
        type="primary",
    )

    st.divider()

    st.caption("Platform")

    st.write("Detection Engine")
    st.write("ML Anomaly Detector")
    st.write("Threat Intelligence")
    st.write("MITRE ATT&CK")
    st.write("RAG Investigation")
    st.write("AI Investigation Agent")
    st.write("SOC Case Management")
    st.write("Automated Reporting")


# ---------------------------------------------------------
# Run pipeline
# ---------------------------------------------------------

if run_pipeline:

    with st.spinner(
        "Running full SOC analysis..."
    ):

        try:

            results = process_alerts(
                alert_file,
                run_ai_investigation=run_ai,
            )

            st.session_state["results"] = results

            # Keep the pipeline-created cases synchronized
            # with the interactive CaseManager.
            pipeline_cases = results.get(
                "cases",
                {},
            )

            case_manager = st.session_state[
                "case_manager"
            ]

            for case in pipeline_cases.values():

                if not isinstance(
                    case,
                    dict,
                ):
                    continue

                case_id = case.get(
                    "case_id"
                )

                if not case_id:
                    continue

                if case_manager.get_case(
                    case_id
                ) is None:

                    case_manager.store.create(
                        case
                    )

            st.success(
                "SOC analysis completed successfully."
            )

        except Exception as exc:

            st.error(
                f"Pipeline execution failed: {exc}"
            )

            st.exception(exc)


# ---------------------------------------------------------
# Wait for analysis
# ---------------------------------------------------------

if "results" not in st.session_state:

    st.info(
        "👈 Configure the alert dataset and click "
        "**Run SOC Analysis** to begin."
    )

    st.markdown("### Platform Architecture")

    col1, col2, col3 = st.columns(3)

    with col1:
        st.markdown(
            """
            **🚨 Detection**

            Rule-based detections identify known
            suspicious activity such as brute force,
            suspicious logins, and suspicious requests.
            """
        )

    with col2:
        st.markdown(
            """
            **🤖 AI Analysis**

            ML anomaly detection, RAG evidence,
            MITRE ATT&CK context, and the AI
            investigation agent enrich alerts.
            """
        )

    with col3:
        st.markdown(
            """
            **📁 SOC Operations**

            Investigations become SOC cases,
            cases generate reports, and analysts
            can review the evidence.
            """
        )

    st.stop()


# ---------------------------------------------------------
# Results
# ---------------------------------------------------------

results = st.session_state["results"]

alerts = results.get("alerts", [])
detections = results.get("detections", {})
anomalies = results.get("anomalies", {})
risks = results.get("risks", {})
iocs = results.get("iocs", {})
enriched_iocs = results.get(
    "enriched_iocs",
    {},
)
mitre = results.get("mitre", {})
investigations = results.get(
    "investigations",
    {},
)
ai_investigations = results.get(
    "ai_investigations",
    {},
)

pipeline_cases = results.get(
    "cases",
    {},
)

report_paths = results.get(
    "report_paths",
    {},
)


# ---------------------------------------------------------
# Helpers
# ---------------------------------------------------------

def get_alert_id(alert):

    if isinstance(
        alert,
        dict,
    ):
        return alert.get(
            "alert_id"
        )

    return None


def get_mapping_value(
    mapping,
    alert_id,
    default=None,
):

    if isinstance(
        mapping,
        dict,
    ):
        return mapping.get(
            alert_id,
            default,
        )

    return default


def normalize_list(value):

    if value is None:
        return []

    if isinstance(
        value,
        list,
    ):
        return value

    if isinstance(
        value,
        dict,
    ):

        nested = value.get(
            "detections"
        )

        if isinstance(
            nested,
            list,
        ):
            return nested

        nested = value.get(
            "techniques"
        )

        if isinstance(
            nested,
            list,
        ):
            return nested

        return [value]

    return [value]


def risk_counts():

    counts = {
        "CRITICAL": 0,
        "HIGH": 0,
        "MEDIUM": 0,
        "LOW": 0,
    }

    for alert in alerts:

        alert_id = get_alert_id(
            alert
        )

        risk = get_mapping_value(
            risks,
            alert_id,
            {},
        )

        if not isinstance(
            risk,
            dict,
        ):
            continue

        level = risk.get(
            "risk_level"
        )

        if level in counts:
            counts[level] += 1

    return counts


def get_live_cases():

    case_manager = st.session_state[
        "case_manager"
    ]

    return {
        case["alert_id"]: case
        for case in case_manager.list_cases()
        if isinstance(
            case,
            dict,
        )
        and case.get("alert_id")
    }


# ---------------------------------------------------------
# Calculate overview
# ---------------------------------------------------------

counts = risk_counts()

anomaly_count = 0

for alert in alerts:

    alert_id = get_alert_id(
        alert
    )

    anomaly = get_mapping_value(
        anomalies,
        alert_id,
        {},
    )

    if (
        isinstance(
            anomaly,
            dict,
        )
        and anomaly.get(
            "is_anomaly",
            False,
        )
    ):
        anomaly_count += 1


# ---------------------------------------------------------
# Overview
# ---------------------------------------------------------

st.markdown(
    '<div class="section-header">SOC Overview</div>',
    unsafe_allow_html=True,
)

m1, m2, m3, m4, m5, m6 = st.columns(6)

m1.metric(
    "Alerts",
    len(alerts),
)

m2.metric(
    "Critical",
    counts["CRITICAL"],
)

m3.metric(
    "High",
    counts["HIGH"],
)

m4.metric(
    "Medium",
    counts["MEDIUM"],
)

m5.metric(
    "Low",
    counts["LOW"],
)

m6.metric(
    "ML Anomalies",
    anomaly_count,
)


# ---------------------------------------------------------
# Main tabs
# ---------------------------------------------------------

tab_overview, tab_alerts, tab_investigation, tab_cases = st.tabs(
    [
        "📊 Overview",
        "🚨 Alert Queue",
        "🔎 Investigation",
        "📁 Cases & Reports",
    ]
)


# =========================================================
# OVERVIEW TAB
# =========================================================

with tab_overview:

    st.subheader(
        "Risk Distribution"
    )

    risk_df = pd.DataFrame(
        {
            "Risk Level": [
                "CRITICAL",
                "HIGH",
                "MEDIUM",
                "LOW",
            ],
            "Alerts": [
                counts["CRITICAL"],
                counts["HIGH"],
                counts["MEDIUM"],
                counts["LOW"],
            ],
        }
    )

    st.bar_chart(
        risk_df.set_index(
            "Risk Level"
        )
    )


    st.subheader(
        "SOC Pipeline"
    )

    pipeline_cols = st.columns(8)

    pipeline_steps = [
        "Ingestion",
        "Detection",
        "ML",
        "Risk",
        "Threat Intel",
        "MITRE",
        "Investigation",
        "Case",
    ]

    for column, step in zip(
        pipeline_cols,
        pipeline_steps,
    ):

        column.success(
            f"✓ {step}"
        )


    st.subheader(
        "Alert Summary"
    )

    overview_rows = []

    for alert in alerts:

        alert_id = get_alert_id(
            alert
        )

        risk = get_mapping_value(
            risks,
            alert_id,
            {},
        )

        anomaly = get_mapping_value(
            anomalies,
            alert_id,
            {},
        )

        detection_list = normalize_list(
            get_mapping_value(
                detections,
                alert_id,
                [],
            )
        )

        overview_rows.append(
            {
                "Alert": alert_id,
                "Event": alert.get(
                    "event_type"
                ),
                "Severity": alert.get(
                    "severity"
                ),
                "Risk": risk.get(
                    "risk_level"
                )
                if isinstance(
                    risk,
                    dict,
                )
                else None,
                "Score": risk.get(
                    "risk_score"
                )
                if isinstance(
                    risk,
                    dict,
                )
                else None,
                "Priority": risk.get(
                    "priority"
                )
                if isinstance(
                    risk,
                    dict,
                )
                else None,
                "ML": (
                    "ANOMALY"
                    if isinstance(
                        anomaly,
                        dict,
                    )
                    and anomaly.get(
                        "is_anomaly",
                        False,
                    )
                    else "NORMAL"
                ),
                "Detections": len(
                    detection_list
                ),
            }
        )

    st.dataframe(
        pd.DataFrame(
            overview_rows
        ),
        use_container_width=True,
        hide_index=True,
    )


# =========================================================
# ALERT QUEUE
# =========================================================

with tab_alerts:

    st.subheader(
        "🚨 SOC Alert Queue"
    )

    live_cases = get_live_cases()

    alert_rows = []

    for alert in alerts:

        alert_id = get_alert_id(
            alert
        )

        risk = get_mapping_value(
            risks,
            alert_id,
            {},
        )

        case = live_cases.get(
            alert_id,
            {},
        )

        alert_rows.append(
            {
                "Alert ID": alert_id,
                "Event Type": alert.get(
                    "event_type"
                ),
                "Severity": alert.get(
                    "severity"
                ),
                "Risk": risk.get(
                    "risk_level"
                )
                if isinstance(
                    risk,
                    dict,
                )
                else None,
                "Score": risk.get(
                    "risk_score"
                )
                if isinstance(
                    risk,
                    dict,
                )
                else None,
                "Priority": risk.get(
                    "priority"
                )
                if isinstance(
                    risk,
                    dict,
                )
                else None,
                "Action": risk.get(
                    "action"
                )
                if isinstance(
                    risk,
                    dict,
                )
                else None,
                "Case": case.get(
                    "case_id"
                )
                if isinstance(
                    case,
                    dict,
                )
                else None,
                "Case Status": case.get(
                    "status"
                )
                if isinstance(
                    case,
                    dict,
                )
                else None,
            }
        )

    st.dataframe(
        pd.DataFrame(
            alert_rows
        ),
        use_container_width=True,
        hide_index=True,
    )


# =========================================================
# INVESTIGATION
# =========================================================

with tab_investigation:

    st.subheader(
        "🔎 Analyst Investigation Console"
    )

    alert_ids = [
        get_alert_id(alert)
        for alert in alerts
        if get_alert_id(alert)
    ]

    selected_alert = st.selectbox(
        "Select Alert",
        alert_ids,
    )

    selected_alert_data = next(
        (
            alert
            for alert in alerts
            if get_alert_id(alert)
            == selected_alert
        ),
        {},
    )

    selected_risk = get_mapping_value(
        risks,
        selected_alert,
        {},
    )

    selected_anomaly = get_mapping_value(
        anomalies,
        selected_alert,
        {},
    )

    selected_detection = get_mapping_value(
        detections,
        selected_alert,
        [],
    )

    selected_iocs = get_mapping_value(
        iocs,
        selected_alert,
        [],
    )

    selected_enriched = get_mapping_value(
        enriched_iocs,
        selected_alert,
        [],
    )

    selected_mitre = get_mapping_value(
        mitre,
        selected_alert,
        [],
    )

    selected_investigation = get_mapping_value(
        investigations,
        selected_alert,
        {},
    )

    selected_ai = get_mapping_value(
        ai_investigations,
        selected_alert,
        None,
    )

    live_cases = get_live_cases()

    selected_case = live_cases.get(
        selected_alert,
        {},
    )


    # -----------------------------------------------------
    # Investigation metrics
    # -----------------------------------------------------

    c1, c2, c3, c4 = st.columns(4)

    c1.metric(
        "Risk",
        selected_risk.get(
            "risk_level",
            "UNKNOWN",
        ),
    )

    c2.metric(
        "Risk Score",
        selected_risk.get(
            "risk_score",
            0,
        ),
    )

    c3.metric(
        "Priority",
        selected_risk.get(
            "priority",
            "UNKNOWN",
        ),
    )

    c4.metric(
        "Case",
        selected_case.get(
            "case_id",
            "N/A",
        ),
    )


    # -----------------------------------------------------
    # Evidence
    # -----------------------------------------------------

    with st.expander(
        "📋 Alert Evidence",
        expanded=True,
    ):

        st.json(
            selected_alert_data
        )


    # -----------------------------------------------------
    # Detections
    # -----------------------------------------------------

    with st.expander(
        "🚨 Detection Evidence",
        expanded=True,
    ):

        detection_list = normalize_list(
            selected_detection
        )

        if detection_list:

            for item in detection_list:

                if isinstance(
                    item,
                    dict,
                ):

                    st.warning(
                        f"{item.get('rule', item.get('detection', 'UNKNOWN'))}"
                        f" — "
                        f"{item.get('severity', 'UNKNOWN')}"
                    )

                else:

                    st.warning(
                        str(item)
                    )

        else:

            st.success(
                "No rule-based detections."
            )


    # -----------------------------------------------------
    # ML
    # -----------------------------------------------------

    with st.expander(
        "🤖 ML Anomaly Analysis"
    ):

        st.json(
            selected_anomaly
        )


    # -----------------------------------------------------
    # Threat Intelligence
    # -----------------------------------------------------

    with st.expander(
        "🌐 Threat Intelligence"
    ):

        st.write(
            "**Extracted IOCs**"
        )

        st.json(
            selected_iocs
        )

        st.write(
            "**Enrichment**"
        )

        st.json(
            selected_enriched
        )


    # -----------------------------------------------------
    # MITRE
    # -----------------------------------------------------

    with st.expander(
        "🎯 MITRE ATT&CK"
    ):

        mitre_list = normalize_list(
            selected_mitre
        )

        if mitre_list:

            rows = []

            for item in mitre_list:

                if isinstance(
                    item,
                    dict,
                ):

                    rows.append(
                        {
                            "Technique ID": item.get(
                                "technique_id",
                                item.get(
                                    "id",
                                    "",
                                ),
                            ),
                            "Technique": item.get(
                                "name",
                                item.get(
                                    "technique_name",
                                    "",
                                ),
                            ),
                            "Tactics": item.get(
                                "tactics",
                                "",
                            ),
                        }
                    )

            if rows:

                st.dataframe(
                    pd.DataFrame(rows),
                    use_container_width=True,
                    hide_index=True,
                )

        else:

            st.info(
                "No MITRE techniques mapped."
            )


    # -----------------------------------------------------
    # Investigation
    # -----------------------------------------------------

    with st.expander(
        "🔎 Investigation Findings",
        expanded=True,
    ):

        st.write(
            selected_investigation.get(
                "summary",
                "No investigation summary.",
            )
        )

        for finding in selected_investigation.get(
            "findings",
            [],
        ):

            st.write(
                f"• {finding}"
            )

        action = selected_investigation.get(
            "recommended_action"
        )

        if action:

            st.info(
                f"Recommended Action: {action}"
            )


    # -----------------------------------------------------
    # AI
    # -----------------------------------------------------

    with st.expander(
        "🧠 AI Investigation"
    ):

        if selected_ai:

            if isinstance(
                selected_ai,
                dict,
            ):

                st.write(
                    f"**Status:** "
                    f"{selected_ai.get('status', 'UNKNOWN')}"
                )

                st.write(
                    f"**Model:** "
                    f"{selected_ai.get('model', 'N/A')}"
                )

                if selected_ai.get(
                    "error"
                ):

                    st.warning(
                        f"Error: "
                        f"{selected_ai['error']}"
                    )

                response = selected_ai.get(
                    "response"
                )

                if response:

                    st.markdown(
                        "##### AI Assessment"
                    )

                    st.write(
                        response
                    )

            else:

                st.write(
                    str(selected_ai)
                )

        else:

            st.info(
                "AI investigation was not run."
            )


# =========================================================
# CASES AND REPORTS
# =========================================================

with tab_cases:

    st.subheader(
        "📁 SOC Cases"
    )

    live_cases = get_live_cases()

    case_rows = []

    for case in live_cases.values():

        if not isinstance(
            case,
            dict,
        ):
            continue

        case_rows.append(
            {
                "Case ID": case.get(
                    "case_id"
                ),
                "Alert ID": case.get(
                    "alert_id"
                ),
                "Status": case.get(
                    "status"
                ),
                "Severity": case.get(
                    "severity"
                ),
                "Risk": case.get(
                    "risk_level"
                ),
                "Priority": case.get(
                    "priority"
                ),
                "Analyst": case.get(
                    "assigned_analyst"
                ),
            }
        )

    if case_rows:

        st.dataframe(
            pd.DataFrame(case_rows),
            use_container_width=True,
            hide_index=True,
        )

    else:

        st.info(
            "No SOC cases available."
        )


    st.divider()

    # -----------------------------------------------------
    # Interactive case management
    # -----------------------------------------------------

    st.subheader(
        "🛠️ Case Management"
    )

    case_ids = [
        case.get("case_id")
        for case in live_cases.values()
        if isinstance(
            case,
            dict,
        )
        and case.get("case_id")
    ]

    if case_ids:

        selected_case_id = st.selectbox(
            "Select Case",
            case_ids,
        )

        case_manager = st.session_state[
            "case_manager"
        ]

        selected_case = case_manager.get_case(
            selected_case_id
        )

        if selected_case:

            info1, info2, info3, info4 = st.columns(4)

            info1.metric(
                "Status",
                selected_case.get(
                    "status",
                    "UNKNOWN",
                ),
            )

            info2.metric(
                "Risk",
                selected_case.get(
                    "risk_level",
                    "UNKNOWN",
                ),
            )

            info3.metric(
                "Priority",
                selected_case.get(
                    "priority",
                    "UNKNOWN",
                ),
            )

            info4.metric(
                "Analyst",
                selected_case.get(
                    "assigned_analyst"
                )
                or "Unassigned",
            )


            # -------------------------------------------------
            # Assignment
            # -------------------------------------------------

            st.markdown(
                "#### 👤 Assign Analyst"
            )

            assign_col1, assign_col2 = st.columns(
                [3, 1]
            )

            with assign_col1:

                analyst_name = st.text_input(
                    "Analyst",
                    value=(
                        selected_case.get(
                            "assigned_analyst"
                        )
                        or ""
                    ),
                    key=(
                        f"analyst_"
                        f"{selected_case_id}"
                    ),
                )

            with assign_col2:

                st.write("")
                st.write("")

                if st.button(
                    "Assign",
                    key=(
                        f"assign_"
                        f"{selected_case_id}"
                    ),
                    use_container_width=True,
                ):

                    try:

                        case_manager.assign_case(
                            selected_case_id,
                            analyst_name,
                        )

                        st.success(
                            "Case assigned successfully."
                        )

                        st.rerun()

                    except Exception as exc:

                        st.error(
                            str(exc)
                        )


            # -------------------------------------------------
            # Status
            # -------------------------------------------------

            st.markdown(
                "#### 🔄 Update Status"
            )

            status_col1, status_col2 = st.columns(
                [3, 1]
            )

            valid_statuses = [
                "OPEN",
                "IN_PROGRESS",
                "CONTAINED",
                "RESOLVED",
                "CLOSED",
            ]

            with status_col1:

                new_status = st.selectbox(
                    "Case Status",
                    valid_statuses,
                    index=(
                        valid_statuses.index(
                            selected_case.get(
                                "status",
                                "OPEN",
                            )
                        )
                        if selected_case.get(
                            "status"
                        ) in valid_statuses
                        else 0
                    ),
                    key=(
                        f"status_"
                        f"{selected_case_id}"
                    ),
                )

            with status_col2:

                st.write("")
                st.write("")

                if st.button(
                    "Update",
                    key=(
                        f"status_btn_"
                        f"{selected_case_id}"
                    ),
                    use_container_width=True,
                ):

                    try:

                        case_manager.update_status(
                            selected_case_id,
                            new_status,
                        )

                        st.success(
                            f"Case status updated to {new_status}."
                        )

                        st.rerun()

                    except Exception as exc:

                        st.error(
                            str(exc)
                        )


            # -------------------------------------------------
            # Evidence
            # -------------------------------------------------

            st.markdown(
                "#### 🔬 Add Evidence"
            )

            evidence_type = st.selectbox(
                "Evidence Type",
                [
                    "Analyst Observation",
                    "IOC",
                    "Log Evidence",
                    "Threat Intelligence",
                    "MITRE ATT&CK",
                    "Other",
                ],
                key=(
                    f"evidence_type_"
                    f"{selected_case_id}"
                ),
            )

            evidence_value = st.text_area(
                "Evidence",
                key=(
                    f"evidence_value_"
                    f"{selected_case_id}"
                ),
                placeholder=(
                    "Describe the evidence "
                    "observed during investigation..."
                ),
            )

            if st.button(
                "➕ Add Evidence",
                key=(
                    f"evidence_btn_"
                    f"{selected_case_id}"
                ),
            ):

                if not evidence_value.strip():

                    st.error(
                        "Evidence cannot be empty."
                    )

                else:

                    evidence = {
                        "type": evidence_type,
                        "value": evidence_value.strip(),
                    }

                    try:

                        case_manager.add_evidence(
                            selected_case_id,
                            evidence,
                        )

                        st.success(
                            "Evidence added."
                        )

                        st.rerun()

                    except Exception as exc:

                        st.error(
                            str(exc)
                        )


            # -------------------------------------------------
            # Analyst Notes
            # -------------------------------------------------

            st.markdown(
                "#### 📝 Analyst Note"
            )

            note = st.text_area(
                "Note",
                key=(
                    f"note_"
                    f"{selected_case_id}"
                ),
                placeholder=(
                    "Record an investigation observation, "
                    "decision, or next step..."
                ),
            )

            if st.button(
                "➕ Add Note",
                key=(
                    f"note_btn_"
                    f"{selected_case_id}"
                ),
            ):

                if not note.strip():

                    st.error(
                        "Note cannot be empty."
                    )

                else:

                    try:

                        case_manager.add_note(
                            selected_case_id,
                            note,
                        )

                        st.success(
                            "Analyst note added."
                        )

                        st.rerun()

                    except Exception as exc:

                        st.error(
                            str(exc)
                        )


            # -------------------------------------------------
            # Close Case
            # -------------------------------------------------

            st.markdown(
                "#### 🔒 Close Case"
            )

            resolution = st.text_area(
                "Resolution",
                key=(
                    f"resolution_"
                    f"{selected_case_id}"
                ),
                placeholder=(
                    "Explain how the case was resolved..."
                ),
            )

            if st.button(
                "🔒 Close Case",
                key=(
                    f"close_"
                    f"{selected_case_id}"
                ),
                type="primary",
            ):

                if not resolution.strip():

                    st.error(
                        "Resolution cannot be empty."
                    )

                else:

                    try:

                        case_manager.close_case(
                            selected_case_id,
                            resolution,
                        )

                        st.success(
                            "Case closed successfully."
                        )

                        st.rerun()

                    except Exception as exc:

                        st.error(
                            str(exc)
                        )


            # -------------------------------------------------
            # Case Evidence / Notes
            # -------------------------------------------------

            st.divider()

            with st.expander(
                "📚 Case Evidence",
                expanded=False,
            ):

                evidence = selected_case.get(
                    "evidence",
                    [],
                )

                if evidence:

                    for index, item in enumerate(
                        evidence,
                        start=1,
                    ):

                        st.markdown(
                            f"**Evidence {index}**"
                        )

                        st.json(
                            item
                        )

                else:

                    st.info(
                        "No analyst-added evidence."
                    )


            with st.expander(
                "📝 Case Notes",
                expanded=False,
            ):

                notes = selected_case.get(
                    "notes",
                    [],
                )

                if notes:

                    for item in notes:

                        timestamp = item.get(
                            "timestamp",
                            "",
                        )

                        note_text = item.get(
                            "note",
                            "",
                        )

                        st.markdown(
                            f"**{timestamp}**"
                        )

                        st.write(
                            note_text
                        )

                else:

                    st.info(
                        "No analyst notes."
                    )


            with st.expander(
                "🧾 Case Details",
                expanded=False,
            ):

                st.json(
                    selected_case
                )


    # -----------------------------------------------------
    # Reports
    # -----------------------------------------------------

    st.divider()

    st.subheader(
        "📄 Generated Reports"
    )

    for alert_id, report_path in report_paths.items():

        if not report_path:
            continue

        path = Path(
            report_path
        )

        st.write(
            f"**{alert_id}** — `{path.name}`"
        )

        try:

            with path.open(
                "rb"
            ) as report_file:

                st.download_button(
                    label=(
                        f"⬇️ Download "
                        f"{path.name}"
                    ),
                    data=report_file,
                    file_name=path.name,
                    mime="application/json",
                    key=(
                        f"download_"
                        f"{alert_id}"
                    ),
                )

        except FileNotFoundError:

            st.warning(
                f"Report not found: {path}"
            )


# ---------------------------------------------------------
# Footer
# ---------------------------------------------------------

st.divider()

st.caption(
    "Full AI SOC Analyst Platform • "
    "Detection → Anomaly → Risk → Threat Intel → "
    "MITRE → Investigation → AI → Case → Report"
)
