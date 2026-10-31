
import json
import tempfile
from collections import Counter
from datetime import datetime
from html import escape
from pathlib import Path

import pandas as pd
import plotly.express as px
from datetime import timedelta, timezone 
import streamlit as st

from loglens.ingest import ingest_file
from loglens.engine.rule_loader import load_rules
from loglens.engine.detector import analyze_events


PROJECT_ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = PROJECT_ROOT / "rules"

SEVERITY_ORDER = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "informational": 4,
    "info": 4,
    "unknown": 5,
}

SEVERITY_COLORS = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#fbbf24",
    "low": "#60a5fa",
    "informational": "#a78bfa",
    "info": "#a78bfa",
    "unknown": "#94a3b8",
}


# ==========================================
# HELPER FUNCTIONS
# ==========================================

def json_safe(value):
    return json.loads(json.dumps(value, default=str))


def clean_text(value, fallback="Not available"):
    if value is None:
        return fallback

    text = str(value).strip()
    return text if text else fallback


def get_severity(finding):
    severity = clean_text(
        finding.get("severity"), "unknown"
    ).lower()

    return severity if severity in SEVERITY_ORDER else "unknown"


def priority_sort_key(finding):
    return SEVERITY_ORDER[get_severity(finding)]


def analyze_uploaded_files(files):
    all_events = []

    with tempfile.TemporaryDirectory() as temp_dir:
        for index, uploaded_file in enumerate(files):
            suffix = Path(uploaded_file.name).suffix.lower()
            temp_path = Path(temp_dir) / f"upload_{index}{suffix}"

            with temp_path.open("wb") as output:
                output.write(uploaded_file.getvalue())

            all_events.extend(ingest_file(temp_path))

    rules = load_rules(RULES_DIR)
    findings = analyze_events(all_events, rules)

    return {
        "total_events": len(all_events),
        "total_findings": len(findings),
        "rules_loaded": len(rules),
        "files_uploaded": len(files),
        "findings": json_safe(findings),
        "events": json_safe([
            event.model_dump() if hasattr(event, "model_dump")
            else event
            for event in all_events
        ]),
    }


def finding_title(finding, number):
    return clean_text(
        finding.get("title"),
        f"Finding {number}",
    )


def get_next_steps(finding):
    steps = finding.get("next_steps") or []

    if isinstance(steps, str):
        return [steps]

    if isinstance(steps, list):
        return [str(step) for step in steps if step]

    return []


def severity_badge(severity):
    color = SEVERITY_COLORS.get(severity, "#94a3b8")

    return (
        f'<span class="severity-badge" '
        f'style="border-color:{color};color:{color};">'
        f'{escape(severity.upper())}'
        f'</span>'
    )


def display_finding(finding, number, expanded=False, events=None):
    """Display a security finding using five clear sections."""

    title = finding_title(finding, number)
    severity = get_severity(finding)

    rule_id = clean_text(finding.get("rule_id"))
    event_id = clean_text(finding.get("event_id"))
    computer = clean_text(finding.get("computer"))
    timestamp = clean_text(finding.get("timestamp"))
    target_user = clean_text(finding.get("target_user"))

    attack = finding.get("attack") or []

    if isinstance(attack, str):
        attack = [attack]

    attack_text = ", ".join(map(str, attack)) or "Not mapped"

    consumer_text = clean_text(
        finding.get("consumer_text"),
        "LogLens identified activity that may need review.",
    )

    false_positive = clean_text(
        finding.get("false_positive_note"),
        "Some security events can happen during normal use.",
    )

    next_steps = get_next_steps(finding)

    analyst_notes = clean_text(
        finding.get("analyst_notes"),
        "No additional technical notes are available.",
    )

    with st.expander(
        f"{number}. {title}  |  {severity.upper()}",
        expanded=expanded,
    ):
        st.markdown(
            severity_badge(severity)
            + f' <span class="rule-label">'
            + f'Rule: {escape(rule_id)}</span>',
            unsafe_allow_html=True,
        )

        st.markdown("#### 1. What happened?")
        st.write(consumer_text)

        st.markdown("#### 2. Where and when?")
        st.write(f"**Computer:** {computer}")
        st.write(f"**Time:** {timestamp}")
        st.write(f"**Windows Event ID:** {event_id}")

        if target_user != "Not available":
            st.write(f"**Account:** {target_user}")

        st.markdown("#### 3. Could this be normal?")
        st.write(false_positive)

        st.markdown("#### 4. Investigation Checklist")

        st.caption(
            "Follow these steps in order. Start with reviewing"
            "the evidece before making changes to the system."
        )

        if next_steps:
            for step_number, step in enumerate(next_steps, 1):
                st.checkbox(
                    f"{step_number}. {step}",
                    key=f"checklist_{number}_{step_number}",
                )
                
                
        else:
            st.checkbox(
                "Ask a trusted computer administrator "
                "to review this activity.",
                key=f"checklist_{number}_default",
            )

        if st.session_state.get("learning_mode") == "Analyst Mode":
            st.markdown("#### 5. Analyst Learning Mode")

            st.write(f"**Detection rule:** {rule_id}")
            st.write(f"**Severity:** {severity.upper()}")
            st.write(f"**Windows Event ID:** {event_id}")

            if event_id.isdigit():
                st.markdown(
                    f"[Learn about Windows Event ID {event_id}]"
                    f"(https://www.ultimatewindowssecurity.com/"
                    f"securitylog/encyclopedia/event.aspx?eventid={event_id})"
                )

            st.markdown("**MITRE ATT&CK techniques:**")
            for technique in attack:
                technique = str(technique)
                if technique.startswith("T"):
                    st.markdown(
                        f"- [{technique}]"
                        f"(https://attack.mitre.org/techniques/"
                        f"{technique.replace('.', '/')}/)"
                    )

            st.write(f"**Analyst notes:** {analyst_notes}")

            st.markdown("**Detection logic:**")
            st.write(
                clean_text(
                    finding.get("detection_logic"),
                    "Review the matching YAML detection rule "
                    "for its conditions and thresholds.",
                )
            )

            st.markdown("**Process relationships:**")
            st.write(
                clean_text(
                    finding.get("parent_name")
                    or finding.get("parent_process"),
                    "No parent process information available "
                    "for this finding.",
                )
            )

        else:
            st.markdown("#### 5. Learning Notes")
            st.write(
                "LogLens explains suspicious Windows activity "
                "in everyday language. A finding is a reason "
                "to investigate, not proof of an attack."
            )
        with st.popover("View original finding data"):
            st.json(finding)

        st.divider()

        display_event_timeline(
            finding,
            events or [],
            number,
        )


def display_priority_card(finding, rank):
    """Explain why a finding appears in the priority list."""

    severity = get_severity(finding)
    title = clean_text(finding.get("title"), "Security finding")

    explanation = clean_text(
        finding.get("consumer_text"),
        "This activity may need review.",
    )

    steps = get_next_steps(finding)

    st.markdown(
        '<div class="priority-card">'
        f'<div class="priority-title">'
        f'{rank}. {escape(title)}'
        '</div>'
        f'{severity_badge(severity)}'
        '</div>',
        unsafe_allow_html=True,
    )

    st.markdown("**Why should I look at this?**")
    st.write(explanation)

    if steps:
        st.markdown("**What should I do first?**")
        st.write(steps[0])

    st.caption(
        f"Priority based on the detection rule's "
        f"{severity.upper()} severity. "
        "This is a suggested review order, not proof of an attack."
    )


def display_severity_chart(findings):
    counts = Counter(get_severity(f) for f in findings)

    labels = [
        "Critical",
        "High",
        "Medium",
        "Low",
        "Informational",
        "Unknown",
    ]

    values = [
        counts.get("critical", 0),
        counts.get("high", 0),
        counts.get("medium", 0),
        counts.get("low", 0),
        counts.get("informational", 0)
        + counts.get("info", 0),
        counts.get("unknown", 0),
    ]

    chart_data = pd.DataFrame({
        "Severity": labels,
        "Findings": values,
    }).set_index("Severity")

    st.bar_chart(
        chart_data,
        color="#9874f4",
        use_container_width=True,
    )


def parse_finding_date(finding):
    timestamp = finding.get("timestamp")

    if not timestamp:
        return None

    try:
        parsed = datetime.fromisoformat(
            str(timestamp).replace("Z", "+00:00")
        )
        return parsed.date()
    except (TypeError, ValueError):
        return None


def display_activity_chart(findings):
    dates = [
        parse_finding_date(finding)
        for finding in findings
    ]

    dates = [date for date in dates if date is not None]

    if not dates:
        st.info(
            "No usable finding timestamps are available "
            "for the activity chart."
        )
        return

    counts = Counter(dates)

    chart_data = pd.DataFrame(
        [
            {"Date": date, "Findings": count}
            for date, count in sorted(counts.items())
        ]
    ).set_index("Date")

    st.line_chart(
        chart_data,
        color="#60a5fa",
        use_container_width=True,
    )

    st.caption(
        "Shows detected findings by date, not every Windows event. "
        "Dates with no findings may not appear."
    )

def display_event_timeline(finding, events, number):
    """Show events near a security finding."""

    st.markdown("#### Event Timeline")

    minutes = st.slider(
        "Show events within this many minutes",
        min_value=1,
        max_value=60,
        value=10,
        key=f"timeline_window_{number}",
    )

    timestamp = (
        finding.get("timestamp")
        or finding.get("first_seen")
    )

    try:
        finding_time = datetime.fromisoformat(
            str(timestamp).replace("Z", "+00:00")
        )
        if finding_time.tzinfo is None:
            finding_time = finding_time.replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        st.info("No valid timestamp is available for this finding.")
        return

    rows = []

    for event in events:
        if not isinstance(event, dict):
            continue

        event_timestamp = (
            event.get("timestamp_utc")
            or event.get("timestamp")
        )

        try:
            event_time = datetime.fromisoformat(
                str(event_timestamp).replace("Z", "+00:00")
            )
            if event_time.tzinfo is None:
                event_time = event_time.replace(tzinfo=timezone.utc)
        except (ValueError, TypeError):
            continue

        if abs(event_time - finding_time) > timedelta(minutes=minutes):
            continue

        # Keep the timeline focused on the finding's computer.
        if (
            finding.get("computer")
            and event.get("computer")
            and finding["computer"] != event["computer"]
        ):
            continue

        rows.append({
            "Time": event_time,
            "Event ID": str(event.get("event_id", "Unknown")),
            "Channel": str(event.get("channel", "Unknown")),
            "Type": "Related event",
        })

    rows.append({
        "Time": finding_time,
        "Event ID": str(finding.get("event_id", "Finding")),
        "Channel": "Detection",
        "Type": "Security finding",
    })

    df = pd.DataFrame(rows).sort_values("Time")

    fig = px.scatter(
        df,
        x="Time",
        y="Channel",
        color="Type",
        hover_data=["Event ID"],
        color_discrete_map={
            "Security finding": "#ef4444",
            "Related event": "#9874f4",
        },
        title="Events Around This Finding",
    )

    fig.update_traces(marker=dict(size=12))
    fig.update_layout(
        template="plotly_dark",
        height=350,
        margin=dict(l=20, r=20, t=55, b=20),
        legend_title_text="",
    )

    st.plotly_chart(
        fig,
        use_container_width=True,
        key=f"timeline_chart_{number}",
    )

    st.caption(
        f"Showing {len(rows) - 1} nearby log events "
        f"within ±{minutes} minutes of this finding. "
        "The red marker represents the detection."
    )
# ==========================================
# DASHBOARD STYLING
# ==========================================
def create_attack_navigator_layer(findings):
    """Create a MITRE ATT&CK Navigator layer from findings."""

    technique_counts = Counter()

    for finding in findings:
        if not isinstance(finding, dict):
            continue

        techniques = finding.get("attack") or []

        if isinstance(techniques, str):
            techniques = [techniques]

        for technique in techniques:
            if isinstance(technique, dict):
                technique = (
                    technique.get("technique_id")
                    or technique.get("id")
                )

            if not technique:
                continue

            technique = str(technique).strip().upper()

            import re
            if re.fullmatch(r"T\d{4}(?:\.\d{3})?", technique):
                technique_counts[technique] += 1

    techniques = [
        {
            "techniqueID": technique,
            "score": count,
            "comment": f"Detected in {count} LogLens finding(s).",
            "enabled": True,
        }
        for technique, count in sorted(technique_counts.items())
    ]

    return {
        "name": "LogLens Community Detection Findings",
        "versions": {
            "attack": "18",
            "navigator": "5.1.0",
            "layer": "4.5",
        },
        "domain": "enterprise-attack",
        "description": (
            "MITRE ATT&CK techniques mapped to LogLens "
            "Community security findings."
        ),
        "filters": {
            "platforms": ["Windows"],
        },
        "sorting": 0,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
        },
        "hideDisabled": False,
        "techniques": techniques,
        "gradient": {
            "colors": ["#ffffff", "#9874f4", "#ef4444"],
            "minValue": 0,
            "maxValue": max(technique_counts.values(), default=1),
        },
        "legendItems": [],
        "metadata": [],
        "links": [],
        "showTacticRowBackground": False,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": False,
    }
st.markdown("""
<style>
[data-testid="stMainBlockContainer"] {
    max-width: 1150px !important;
    margin-left: auto !important;
    margin-right: auto !important;
    padding-left: 2rem !important;
    padding-right: 2rem !important;
    box-sizing: border-box !important;
}

.dashboard-label {
    color: #bba6ff;
    font-size: 0.78rem;
    font-weight: 800;
    letter-spacing: 2px;
    margin-bottom: 12px;
}

.dashboard-heading {
    font-size: clamp(2rem, 4vw, 3.1rem);
    font-weight: 800;
    color: #f7f5ff;
    margin-bottom: 10px;
}

.dashboard-description {
    color: #b8bbd4;
    font-size: 1rem;
    margin-bottom: 24px;
}

.section-label {
    color: #f4f1ff;
    font-size: 1.35rem;
    font-weight: 700;
    margin: 20px 0 12px;
}

div[data-testid="stMetric"] {
    background: linear-gradient(145deg, #1d2445, #151b34);
    border: 1px solid #4d4078;
    border-radius: 16px;
    padding: 18px;
    min-height: 125px;
}

div[data-testid="stMetricValue"] {
    color: #ffffff;
}

div[data-testid="stFileUploader"] {
    background: #171e38;
    border: 1px solid #6351a0;
    border-radius: 16px;
    padding: 14px;
}

[data-testid="stFileUploaderDropzone"] {
    background: #202746 !important;
    border: 1px dashed #9b80ee !important;
}

[data-testid="stFileUploaderDropzone"] * {
    color: #f0ebff;
}

div.stButton button[kind="primary"] {
    background: linear-gradient(
        90deg, #704de2, #8a62ed, #418de9
    ) !important;
    color: #ffffff !important;
    border: none !important;
    border-radius: 10px !important;
    min-height: 48px;
    font-weight: 700;
}

div[data-testid="stExpander"] {
    background: #171e38;
    border: 1px solid #403565;
    border-radius: 14px;
    margin-bottom: 10px;
}

div[data-testid="stExpander"] summary {
    color: #f1ecff !important;
    font-weight: 600;
}

div[data-testid="stExpander"] details {
    background: #171e38;
}

div[data-testid="stExpander"] h4 {
    color: #bda8ff !important;
    margin-top: 18px;
}

.priority-card {
    background: linear-gradient(145deg, #252345, #1b213c);
    border: 1px solid #6753a1;
    border-radius: 12px;
    padding: 16px;
    margin: 14px 0 12px;
}

.priority-title {
    font-size: 1.05rem;
    font-weight: 750;
    color: #ffffff;
    margin-bottom: 12px;
}

.severity-badge {
    display: inline-block;
    border: 1px solid;
    border-radius: 999px;
    padding: 4px 11px;
    font-size: 0.72rem;
    font-weight: 800;
    letter-spacing: 0.5px;
}

.rule-label {
    color: #b8bbd4;
    font-size: 0.85rem;
    margin-left: 10px;
}

@media (max-width: 768px) {
    [data-testid="stMainBlockContainer"] {
        padding-left: 1rem !important;
        padding-right: 1rem !important;
    }
}
</style>
""", unsafe_allow_html=True)


# ==========================================
# DASHBOARD HEADER
# ==========================================

name = st.session_state.get("display_name") or "Analyst"

st.markdown(
    '<div class="dashboard-label">'
    'LOGLENS COMMUNITY / SECURITY WORKSPACE'
    '</div>',
    unsafe_allow_html=True,
)

st.markdown(
    '<div class="dashboard-heading">Security Dashboard</div>',
    unsafe_allow_html=True,
)

st.markdown(
    f'<div class="dashboard-description">'
    f'Welcome back, {escape(str(name))}! '
    f'Analyze Windows event logs and review security findings.'
    f'</div>',
    unsafe_allow_html=True,
)

st.divider()


# ==========================================
# SECURITY OVERVIEW
# ==========================================

st.markdown(
    '<div class="section-label">Security Overview</div>',
    unsafe_allow_html=True,
)

results = st.session_state.get("analysis_results")

total_events = results["total_events"] if results else 0
total_findings = results["total_findings"] if results else 0
rules_loaded = results["rules_loaded"] if results else 0
files_uploaded = results["files_uploaded"] if results else 0

col1, col2, col3, col4 = st.columns(4)

col1.metric("Events Analyzed", f"{total_events:,}")
col2.metric("Security Findings", total_findings)
col3.metric("Rules Loaded", rules_loaded)
col4.metric("Files Analyzed", files_uploaded)

st.divider()


# ==========================================
# FILE UPLOAD
# ==========================================

st.markdown(
    '<div class="section-label">Analyze Windows Logs</div>',
    unsafe_allow_html=True,
)

st.write(
    "Upload Windows Security, Sysmon, or System event logs "
    "in EVTX, CSV, or JSON format."
)

uploaded_files = st.file_uploader(
    "Select your log files",
    type=["evtx", "csv", "json"],
    accept_multiple_files=True,
    key="dashboard_files",
)

if uploaded_files:
    st.success(f"{len(uploaded_files)} file(s) selected.")

    for uploaded_file in uploaded_files:
        st.write(f"📄 {uploaded_file.name}")

    if st.button(
        "Analyze Logs",
        type="primary",
        use_container_width=True,
    ):
        try:
            with st.spinner("Analyzing Windows security events..."):
                st.session_state.analysis_results = (
                    analyze_uploaded_files(uploaded_files)
                )

            st.rerun()

        except Exception as error:
            st.error(f"Analysis failed: {error}")
            st.exception(error)
else:
    st.info("Select at least one log file to begin analysis.")

st.divider()


# ==========================================
# FIVE-LINE SECURITY SUMMARY
# ==========================================

results = st.session_state.get("analysis_results")

if results:
    st.markdown(
        '<div class="section-label">Your Security Summary</div>',
        unsafe_allow_html=True,
    )

    st.write(
        f"1. LogLens checked {results['total_events']:,} "
        "Windows events."
    )

    st.write(
        f"2. It found {results['total_findings']} "
        "activities that may need review."
    )

    st.write(
        f"3. It used {results['rules_loaded']} "
        "security detection rules."
    )

    st.write(
        f"4. The results came from "
        f"{results['files_uploaded']} uploaded file(s)."
    )

    st.write(
        "5. Review the findings below to understand "
        "what happened and what to check next."
    )

    st.divider()


# ==========================================
# SECURITY CHARTS
# ==========================================

if results:
    findings = [
        finding
        for finding in results["findings"]
        if isinstance(finding, dict)
    ]

    st.markdown(
        '<div class="section-label">Security Charts</div>',
        unsafe_allow_html=True,
    )

    if findings:
        chart_col1, chart_col2 = st.columns(2)

        with chart_col1:
            st.markdown("**Findings by Severity**")
            display_severity_chart(findings)

        with chart_col2:
            st.markdown("**Security Findings Over Time**")
            display_activity_chart(findings)

    else:
        st.info("Charts will appear when findings are detected.")

    st.divider()


# ==========================================
# CRITICAL SECURITY ALERTS
# ==========================================

if results:
    st.markdown(
        '<div class="section-label">Critical Security Alerts</div>',
        unsafe_allow_html=True,
    )

    critical_findings = [
        finding
        for finding in findings
        if get_severity(finding) == "critical"
    ]

    if critical_findings:
        st.error(
            f"{len(critical_findings)} critical finding(s) detected. "
            "Review these as soon as possible."
        )

        for number, finding in enumerate(
            critical_findings, start=1
        ):
            display_priority_card(finding, number)

    else:
        st.success(
            "No critical findings detected by the current rules."
        )
        st.caption(
            "This does not mean the computer is completely safe. "
            "High, Medium, and Low findings may still need review."
        )

    st.divider()


# ==========================================
# INVESTIGATE THESE FIRST
# ==========================================

if results:
    st.markdown(
        '<div class="section-label">'
        'Investigate These First'
        '</div>',
        unsafe_allow_html=True,
    )

    st.write(
        "Not sure where to start? LogLens suggests reviewing "
        "higher-severity findings first."
    )

    if findings:
        sorted_findings = sorted(
            findings,
            key=priority_sort_key,
        )

        # Show up to three distinct rules to avoid repeating
        # the same explanation several times.
        priority_findings = []
        seen_rules = set()

        for finding in sorted_findings:
            rule_id = clean_text(
                finding.get("rule_id"),
                finding.get("title", "Unknown"),
            )

            if rule_id in seen_rules:
                continue

            seen_rules.add(rule_id)
            priority_findings.append(finding)

            if len(priority_findings) == 3:
                break

        for number, finding in enumerate(
            priority_findings, start=1
        ):
            display_priority_card(finding, number)

        st.caption(
            "This list highlights up to three different "
            "detection rules. Other findings may have the "
            "same severity and also deserve attention."
        )

    else:
        st.info(
            "No findings are available to prioritize."
        )

    st.divider()


# ==========================================
# DETECTION FINDINGS AND FILTERS
# ==========================================
st.markdown("### Learning Mode")

learning_mode = st.radio(
    "Choose how you want to explore security findings:",
    ["Consumer Mode", "Analyst Mode"],
    horizontal=True,
    key="learning_mode",
)

if learning_mode == "Consumer Mode":
    st.caption(
        "Beginner-friendly explanations of suspicious activity."
    )
else:
    st.caption(
        "Technical investigation details for security analysts."
    )
st.markdown(
    '<div class="section-label">Detection Findings</div>',
    unsafe_allow_html=True,
)

results = st.session_state.get("analysis_results")

if results is None:
    st.info(
        "Your security findings will appear here after analysis."
    )

else:
    all_findings = results["findings"]

    valid_findings = [
        finding
        for finding in all_findings
        if isinstance(finding, dict)
    ]

    if not all_findings:
        st.success(
            "No suspicious activity was identified "
            "by the loaded detection rules."
        )
        st.caption(
            "This does not guarantee that the system "
            "is free from security threats."
        )

    else:
        st.write(
            f"LogLens generated {len(all_findings)} finding(s)."
        )

        filter_col1, filter_col2 = st.columns(2)

        with filter_col1:
            selected_severity = st.selectbox(
                "Filter by severity",
                [
                    "All",
                    "Critical",
                    "High",
                    "Medium",
                    "Low",
                    "Informational",
                    "Unknown",
                ],
                key="finding_severity_filter",
            )

        with filter_col2:
            sort_order = st.selectbox(
                "Sort findings",
                [
                    "Highest priority first",
                    "Lowest priority first",
                    "Original order",
                ],
                key="finding_sort_order",
            )

        filtered_findings = valid_findings

        if selected_severity != "All":
            selected = selected_severity.lower()

            if selected == "informational":
                filtered_findings = [
                    finding
                    for finding in valid_findings
                    if get_severity(finding)
                    in ("informational", "info")
                ]
            else:
                filtered_findings = [
                    finding
                    for finding in valid_findings
                    if get_severity(finding) == selected
                ]

        if sort_order == "Highest priority first":
            filtered_findings = sorted(
                filtered_findings,
                key=priority_sort_key,
            )

        elif sort_order == "Lowest priority first":
            filtered_findings = sorted(
                filtered_findings,
                key=priority_sort_key,
                reverse=True,
            )

        st.caption(
            f"Showing {len(filtered_findings)} of "
            f"{len(valid_findings)} standard finding cards."
        )

        if not filtered_findings:
            st.info(
                "No findings match this severity filter."
            )

        for number, finding in enumerate(
            filtered_findings, start=1
        ):
            display_finding(
                finding,
                number,
                expanded=number == 1,
                events=results.get("events", [])
            )

        invalid_findings = [
            finding
            for finding in all_findings
            if not isinstance(finding, dict)
        ]

        if invalid_findings:
            st.warning(
                f"{len(invalid_findings)} finding(s) could not "
                "be displayed as standard cards."
            )

            with st.expander("View unformatted findings"):
                for finding in invalid_findings:
                    st.json(finding)

    report = {
        "total_events": results["total_events"],
        "total_findings": results["total_findings"],
        "rules_loaded": results["rules_loaded"],
        "files_uploaded": results["files_uploaded"],
        "findings": all_findings,
    }

    st.download_button(
        "Download JSON Report",
        data=json.dumps(report, indent=2, default=str),
        file_name="loglens_findings.json",
        mime="application/json",
        type="primary",
    )
    st.divider()

    st.markdown("### MITRE ATT&CK Navigator Export")

    st.write(
        "Download a Navigator layer to visualize the "
        "MITRE ATT&CK techniques identified by LogLens."
    )

    navigator_layer = create_attack_navigator_layer(
        valid_findings
    )

    st.download_button(
        label="Download ATT&CK Navigator Layer",
        data=json.dumps(navigator_layer, indent=2),
        file_name="loglens_attack_navigator.json",
        mime="application/json",
        type="secondary",
    )

