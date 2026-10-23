
import streamlit as st
import streamlit.components.v1 as components

 #==========================================
# 1. ANIMATED BLUE SHIELD
# ==========================================

def show_shield():
    """Display a rotating blue 3D-style shield."""

    components.html("""
    <!DOCTYPE html>
    <html>
    <head>
    <style>
        * {
            box-sizing: border-box;
        }

        body {
            margin: 0;
            height: 300px;
            display: flex;
            justify-content: center;
            align-items: center;
            background: transparent;
            overflow: hidden;
        }

        .scene {
            position: relative;
            width: 240px;
            height: 270px;
            perspective: 900px;
            display: flex;
            justify-content: center;
            align-items: center;
        }

        .shield {
            position: relative;
            width: 165px;
            height: 205px;
            transform-style: preserve-3d;
            animation: spin 7s linear infinite;
        }

        .face {
            position: absolute;
            inset: 0;
            backface-visibility: hidden;
        }

        .front {
            transform: translateZ(8px);
        }

        .back {
            transform: rotateY(180deg) translateZ(8px);
        }

        .middle {
            position: absolute;
            inset: 0;
            transform: translateZ(0);
        }

        svg {
            width: 100%;
            height: 100%;
            overflow: visible;
        }

        .glow {
            position: absolute;
            width: 180px;
            height: 180px;
            background: #087bff;
            opacity: 0.12;
            filter: blur(45px);
            border-radius: 50%;
            pointer-events: none;
        }

        @keyframes spin {
            from {
                transform: rotateY(0deg) rotateX(8deg);
            }
            to {
                transform: rotateY(360deg) rotateX(8deg);
            }
        }

        @media (prefers-reduced-motion: reduce) {
            .shield {
                animation: none;
            }
        }
    </style>
    </head>

    <body>
        <div class="scene">
            <div class="glow"></div>

            <div class="shield">

                <div class="middle">
                    <svg viewBox="0 0 180 215">
                        <path
                            d="M90 8 L165 38 L155 128
                               Q143 174 90 204
                               Q37 174 25 128 L15 38 Z"
                            fill="#0064c8"
                            stroke="#009dff"
                            stroke-width="12"
                        />
                    </svg>
                </div>

                <div class="face front">
                    <svg viewBox="0 0 180 215">
                        <defs>
                            <linearGradient
                                id="metal"
                                x1="0%" y1="0%"
                                x2="100%" y2="100%">
                                <stop offset="0%"
                                      stop-color="#a4f5ff"/>
                                <stop offset="25%"
                                      stop-color="#219cff"/>
                                <stop offset="65%"
                                      stop-color="#0753b7"/>
                                <stop offset="100%"
                                      stop-color="#061b48"/>
                            </linearGradient>
                        </defs>

                        <path
                            d="M90 8 L165 38 L155 128
                               Q143 174 90 204
                               Q37 174 25 128 L15 38 Z"
                            fill="url(#metal)"
                            stroke="#6feaff"
                            stroke-width="5"
                        />

                        <path
                            d="M90 30 L143 51 L135 123
                               Q126 155 90 179
                               Q54 155 45 123 L37 51 Z"
                            fill="none"
                            stroke="#b6f5ff"
                            stroke-width="2"
                            opacity="0.7"
                        />

                        <path
                            d="M57 103 L80 126 L125 77"
                            fill="none"
                            stroke="#d0ffff"
                            stroke-width="11"
                            stroke-linecap="round"
                            stroke-linejoin="round"
                        />
                    </svg>
                </div>

                <div class="face back">
                    <svg viewBox="0 0 180 215">
                        <path
                            d="M90 8 L165 38 L155 128
                               Q143 174 90 204
                               Q37 174 25 128 L15 38 Z"
                            fill="#073b89"
                            stroke="#28cfff"
                            stroke-width="6"
                        />

                        <path
                            d="M90 34 L138 54 L132 120
                               Q125 153 90 175
                               Q55 153 48 120 L42 54 Z"
                            fill="none"
                            stroke="#61dfff"
                            stroke-width="3"
                        />
                    </svg>
                </div>

            </div>
        </div>
    </body>
    </html>
    """, height=300)
  



st.markdown(
    '<div class="brand">'
    '◈ LOGLENS COMMUNITY / SECURITY INTELLIGENCE'
    '</div>',
    unsafe_allow_html=True,
)

#Display the shield 
show_shield()

# Display a welcome heading
st.markdown("""
    <div class="hero-title">
        WELCOME TO<br>
        <span class="gradient-text">
            LOGLENS COMMUNITY!
        </span>
    </div>

    <div class="subtitle">
        Cybersecurity made simple.
        Security insights made powerful.
    </div>
""", unsafe_allow_html=True)

st.write(
    "Explore your Windows security events "
    "through an easy-to-use security dashboard."
)

if st.button(
    "Get Started →",
    type="primary",
    use_container_width=True,
):
    st.switch_page("pages/dashboard.py")
