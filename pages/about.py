
import streamlit as st

st.title("About LogLens Community")

st.markdown(
    "### Making cybersecurity easier to understand"
)

st.write(
    "LogLens Community is a cybersecurity log analysis "
    "application designed to help people understand "
    "Windows security events without requiring "
    "advanced cybersecurity knowledge."
)

st.divider()

st.subheader("What Does LogLens Do?")

st.write(
    "LogLens processes Windows event logs and uses "
    "detection rules to identify activities that "
    "may need further investigation."
)

st.markdown("""
**LogLens can help you:**

- Analyze Windows Security, Sysmon, and System logs.
- Identify potentially suspicious activity.
- Understand findings through plain-language explanations.
- Learn what actions to consider next.
""")

st.divider()

st.subheader("How It Works")

st.markdown("""
1. **Upload:** Select a Windows event log.
2. **Analyze:** LogLens processes events and applies detection rules.
3. **Understand:** Review findings in simple language.
4. **Respond:** Follow suggested next steps when appropriate.
""")

st.divider()

st.subheader("Technology Behind LogLens")

st.write(
    "LogLens Community uses Python, Streamlit, "
    "Windows Event Logs, Sysmon, YAML detection rules, "
    "and MITRE ATT&CK mappings."
)

st.divider()

st.subheader("Important Limitations")

st.info(
    "LogLens highlights potentially suspicious events. "
    "A finding does not automatically mean an attack "
    "occurred. Results depend on the available logs "
    "and the detection rules supported by the application."
)
