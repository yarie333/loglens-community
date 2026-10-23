
import streamlit as st
import streamlit.components.v1 as components
from datetime import datetime
from html import escape

# ==========================================
# 1. PAGE CONFIGURATION
# ==========================================

st.set_page_config(
    page_title="LogLens Community",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ==========================================
# 2. SESSION STATE
# ==========================================

if "display_name" not in st.session_state:
    st.session_state.display_name = ""

if "entered" not in st.session_state:
    st.session_state.entered = False


# ==========================================
# 3. COMPLETE WEBSITE CSS
# ==========================================

st.markdown("""
<style>

/* MAIN WEBSITE BACKGROUND */

html, body, [data-testid="stAppViewContainer"],
.stApp {
    background: #080e20;
    color: #edf2ff;
}

.stApp {
    background:
        radial-gradient(
            ellipse at 80% 12%,
            rgba(59, 37, 118, 0.45),
            transparent 48%
        ),
        linear-gradient(
            135deg,
            #080e20 0%,
            #10172d 65%,
            #101b37 100%
        );
}

/* FIX HEADER AND CUT-OFF CONTENT */

[data-testid="stHeader"] {
    background: #080e20 !important;
    height: 3.5rem;
}

[data-testid="stToolbar"] {
    color: #ffffff !important;
}

[data-testid="stAppViewBlockContainer"],
.block-container {
    max-width: 1250px !important;
    padding-top: 5.5rem !important;
    padding-bottom: 3rem !important;
}

/* HIDE UNUSED SIDEBAR */

[data-testid="stSidebar"] {
    background: #10172d;
}

/* TYPOGRAPHY */

h1, h2, h3, h4 {
    color: #f8faff !important;
}

p, label {
    color: #cbd5ed;
}

/* TOP BRAND */

.brand {
    color: #9fcaff;
    font-size: 0.85rem;
    font-weight: 800;
    letter-spacing: 3px;
    padding: 12px 0 24px 0;
}

/* WELCOME HEADING */

.hero-title {
    font-size: clamp(2.1rem, 5vw, 4.3rem);
    font-weight: 850;
    color: #ffffff;
    text-align: center;
    line-height: 1.2;
    margin: 0.5rem 0 1rem;
}

.gradient-text {
    background: linear-gradient(
        90deg,
        #a99cff,
        #75baff,
        #31ddf5
    );
    -webkit-background-clip: text;
    background-clip: text;
    -webkit-text-fill-color: transparent;
}

.subtitle {
    text-align: center;
    color: #aebddd;
    font-size: 1.1rem;
    margin-bottom: 2rem;
}

/* GLASS CARDS */

.glass-card {
    background: rgba(26, 38, 70, 0.75);
    border: 1px solid rgba(104, 158, 255, 0.25);
    border-radius: 18px;
    padding: 24px;
    margin: 12px 0;
    color: #e5edff;
    box-shadow: 0 8px 32px rgba(0, 0, 0, 0.15);
}

/* FORM */

[data-testid="stForm"] {
    background: rgba(16, 25, 48, 0.75);
    border: 1px solid rgba(110, 149, 255, 0.2);
    border-radius: 18px;
    padding: 22px;
}

/* TEXT INPUT */

div[data-testid="stTextInput"] input {
    background: #182540 !important;
    color: #ffffff !important;
    border: 1px solid #45649d !important;
    border-radius: 10px !important;
    min-height: 48px;
}

div[data-testid="stTextInput"] input::placeholder {
    color: #a7b6d1 !important;
}

div[data-testid="stTextInput"] input:focus {
    border-color: #39c9ff !important;
    box-shadow: 0 0 0 1px #39c9ff !important;
}

/* PRIMARY BUTTONS */

div[data-testid="stFormSubmitButton"] button,
div.stButton button[kind="primary"] {
    background: linear-gradient(
        90deg,
        #245bde,
        #398cff,
        #27b9e9
    ) !important;
    color: #ffffff !important;
    border: none !important;
    border-radius: 12px !important;
    min-height: 50px;
    font-weight: 700 !important;
    transition: all 0.2s ease;
}

div[data-testid="stFormSubmitButton"] button:hover,
div.stButton button[kind="primary"]:hover {
    filter: brightness(1.15);
    box-shadow: 0 0 20px rgba(44, 152, 255, 0.35);
}

/* SECONDARY BUTTONS */

div.stButton button[kind="secondary"] {
    background: #1a2947 !important;
    color: #dceaff !important;
    border: 1px solid #49659b !important;
    border-radius: 12px !important;
    min-height: 45px;
}

div.stButton button[kind="secondary"]:hover {
    border-color: #47cfff !important;
    color: #ffffff !important;
}

/* FILE UPLOAD AREA */

div[data-testid="stFileUploader"] {
    background: rgba(24, 37, 67, 0.75);
    border: 1px solid #365d9c;
    border-radius: 18px;
    padding: 14px;
}

[data-testid="stFileUploaderDropzone"] {
    background: #172540 !important;
    border: 1px dashed #408bdf !important;
    border-radius: 12px !important;
}

[data-testid="stFileUploaderDropzone"] button {
    background: #244e8e !important;
    color: #ffffff !important;
    border: 1px solid #4b9af0 !important;
}

[data-testid="stFileUploaderDropzone"] * {
    color: #e0ecff;
}

/* SECURITY METRICS */

div[data-testid="stMetric"] {
    background: rgba(25, 39, 74, 0.9);
    border: 1px solid rgba(80, 144, 255, 0.3);
    border-radius: 16px;
    padding: 22px;
    min-height: 135px;
}

div[data-testid="stMetricLabel"] {
    color: #b7c7e7;
}

div[data-testid="stMetricValue"] {
    color: #ffffff;
    font-weight: 800;
}

/* DIVIDERS */

hr {
    border-color: rgba(118, 157, 218, 0.2);
}

/* CAPTIONS */

[data-testid="stCaptionContainer"] {
    color: #a7b8d6;
}

/* MOBILE LAYOUT */

@media (max-width: 768px) {
    [data-testid="stAppViewBlockContainer"],
    .block-container {
        padding-top: 4.5rem !important;
        padding-left: 1rem !important;
        padding-right: 1rem !important;
    }

    .brand {
        font-size: 0.65rem;
        letter-spacing: 2px;
    }

    .hero-title {
        font-size: 2rem;
    }
}

</style>
""", unsafe_allow_html=True)



# ==========================================
# 4. WEBSITE NAVIGATION
# ==========================================

home = st.Page(
    "home.py",
    title="Home",
    icon="🏠",
    default=True,
)

dashboard = st.Page(
    "pages/dashboard.py",
    title="Dashboard",
    icon="📊",
)

about = st.Page(
    "pages/about.py",
    title="About",
    icon="ℹ️",
)

navigation = st.navigation(
    [home, dashboard, about],
    position="top",
)

navigation.run()
