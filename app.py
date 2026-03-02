import streamlit as st
import pandas as pd
import joblib
from datetime import datetime
from pathlib import Path
import math

from extract_features import extract  # نفس extractor اللي دربت عليه

# ===== Load saved model + columns =====
model = joblib.load("smartshield_model.joblib")
FEATURE_COLUMNS = joblib.load("feature_columns.joblib")

LOG_FILE = Path("scan_logs.csv")

# ===== Helpers =====
def build_feature_df(url: str):
    feats = extract(url)
    if feats is None:
        return None, None
    row = {c: float(feats.get(c, 0)) for c in FEATURE_COLUMNS}
    return pd.DataFrame([row]), feats

def risk_label(prob: float):
    if prob >= 0.70:
        return "HIGH", "High Risk – Potentially Malicious"
    elif prob >= 0.40:
        return "MEDIUM", "Medium Risk – Suspicious"
    return "LOW", "Low Risk – Likely Safe"

def risk_color(level: str):
    if level == "HIGH":
        return "red"
    if level == "MEDIUM":
        return "orange"
    return "green"

def save_log(row: dict):
    df = pd.DataFrame([row])
    if LOG_FILE.exists():
        old = pd.read_csv(LOG_FILE)
        out = pd.concat([old, df], ignore_index=True)
    else:
        out = df
    out.to_csv(LOG_FILE, index=False)

def byte_entropy(data: bytes) -> float:
    n = len(data)
    if n == 0:
        return 0.0
    freq = [0] * 256
    for b in data:
        freq[b] += 1
    ent = 0.0
    for c in freq:
        if c:
            p = c / n
            ent -= p * math.log2(p)
    return ent

def top_feature_contributions(feats: dict, top_k: int = 8):
    """
    تفسير مبسط:
    - نعرض أكبر القيم في الميزات اللي غالبًا ترتبط بالتصيد (طول، كلمات مشبوهة، شرطات…)
    - بدون SHAP عشان يبقى بسيط وثابت
    """
    candidates = [
        "url_length","entropy","suspicious_word_count","digit_count","special_char_count",
        "subdomain_count","dash_count","num_params","suspicious_tld","domain_repeat",
        "path_length","query_length","https_flag"
    ]
    pairs = []
    for k in candidates:
        if k in feats:
            pairs.append((k, feats.get(k)))
    pairs.sort(key=lambda x: float(x[1]) if x[1] is not None else 0.0, reverse=True)
    return pairs[:top_k]

# ===== Page setup =====
st.set_page_config(page_title="SmartShield AI", page_icon="🛡️", layout="wide")

st.title("🛡️ SmartShield AI")
st.caption("Commercial-style defensive scanner (URL + File) with saved ML model and audit logging")

# ===== Sidebar =====
st.sidebar.header("Settings")
high_th = st.sidebar.slider("High Risk Threshold", 0.50, 0.95, 0.70, 0.01)
med_th  = st.sidebar.slider("Medium Risk Threshold", 0.10, 0.80, 0.40, 0.01)

show_features = st.sidebar.checkbox("Show extracted features", value=False)
enable_logging = st.sidebar.checkbox("Enable scan logging (CSV)", value=True)

st.sidebar.divider()
st.sidebar.write("Log file:")
st.sidebar.code(str(LOG_FILE))

tabs = st.tabs(["🔗 URL Scan", "📁 File Scan (Static)", "📊 Logs"])

# ===== URL Scan =====
with tabs[0]:
    st.subheader("URL Risk Analysis")
    colA, colB = st.columns([2, 1])

    with colA:
        url_input = st.text_input("Enter URL", placeholder="example: google.com أو https://github.com/login")

        scan_btn = st.button("Scan URL", type="primary")

    with colB:
        st.markdown("### Risk Gauge")
        st.write("Shows risk score based on ML probability.")

    if scan_btn:
        if not url_input.strip():
            st.warning("اكتب رابط أول")
        else:
            df_feat, raw_feats = build_feature_df(url_input.strip())
            if df_feat is None:
                st.error("تعذر استخراج ميزات من الرابط. جرّب صيغة مختلفة.")
            else:
                prob = float(model.predict_proba(df_feat)[0][1])
                score = int(round(prob * 100))

                # Custom thresholds from sidebar
                if prob >= high_th:
                    level = "HIGH"
                    msg = "High Risk – Potentially Malicious"
                elif prob >= med_th:
                    level = "MEDIUM"
                    msg = "Medium Risk – Suspicious"
                else:
                    level = "LOW"
                    msg = "Low Risk – Likely Safe"

                # Result cards
                st.markdown("### Result")
                c1, c2, c3 = st.columns(3)
                c1.metric("Risk Score", f"{score}%")
                c2.metric("Probability", f"{prob:.4f}")
                c3.metric("Verdict", level)

                # Gauge-like progress bar
                st.progress(score / 100.0)

                if level == "HIGH":
                    st.error(f"⚠️ {msg}")
                elif level == "MEDIUM":
                    st.warning(f"⚠️ {msg}")
                else:
                    st.success(f"✅ {msg}")

                # Top features (simple explainability)
                st.markdown("### Why this score?")
                top = top_feature_contributions(raw_feats, top_k=8)
                if top:
                    df_top = pd.DataFrame(top, columns=["Feature", "Value"])
                    st.dataframe(df_top, use_container_width=True, hide_index=True)

                if show_features:
                    with st.expander("All extracted features"):
                        st.json(raw_feats)

                # Logging
                if enable_logging:
                    save_log({
                        "timestamp": datetime.now().isoformat(timespec="seconds"),
                        "type": "URL",
                        "input": url_input.strip(),
                        "risk_score": score,
                        "probability": round(prob, 6),
                        "verdict": level
                    })
                    st.info("Saved to scan_logs.csv")

# ===== File Scan =====
with tabs[1]:
    st.subheader("File Static Check (Entropy-based)")
    st.write("Note: Current ML model is trained for URLs. For files, we run static entropy heuristic (safe).")

    up = st.file_uploader("Upload file", type=None)

    if up is not None:
        data = up.read()
        size = len(data)
        ent = byte_entropy(data)

        c1, c2, c3 = st.columns(3)
        c1.metric("File Name", up.name)
        c2.metric("Size (bytes)", size)
        c3.metric("Byte Entropy", f"{ent:.4f}")

        # Simple verdict
        if ent >= 7.2:
            verdict = "SUSPICIOUS"
            st.error("⚠️ High entropy (possible packing/encryption). Needs deeper analysis.")
        elif ent >= 6.5:
            verdict = "REVIEW"
            st.warning("⚠️ Medium entropy. Recommend additional checks (YARA/Sandbox).")
        else:
            verdict = "LOW_RISK"
            st.success("✅ Low entropy. Likely benign (not guaranteed).")

        if enable_logging:
            save_log({
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "type": "FILE",
                "input": up.name,
                "risk_score": "",
                "probability": "",
                "verdict": verdict
            })
            st.info("Saved to scan_logs.csv")

# ===== Logs =====
with tabs[2]:
    st.subheader("Scan Logs")
    if LOG_FILE.exists():
        logs = pd.read_csv(LOG_FILE)
        st.dataframe(logs.tail(200), use_container_width=True)
        st.download_button(
            "Download Logs CSV",
            data=LOG_FILE.read_bytes(),
            file_name="scan_logs.csv",
            mime="text/csv"
        )
    else:
        st.info("No logs yet. Run a scan first.")