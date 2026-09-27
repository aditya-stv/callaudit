# app.py
import streamlit as st
import os
import pandas as pd
import matplotlib.pyplot as plt
import numpy as np
from datetime import datetime, timedelta
import plotly.express as px
import plotly.graph_objects as go

# helper imports (must exist)
from helper import (
    adb_devices,
    fetch_call_log_raw,
    fetch_contacts_raw,
    parse_content_query,
    parse_contacts,
    normalize_phone_number,
    fetch_device_props,
    fetch_battery,
    fetch_meminfo,
    fetch_uptime,
)

# preprocessor imports (must exist)
from preprocessor import (
    normalize_dataframe,
    most_frequent,
    calls_by_hour,
    calls_per_day,
    calls_heatmap,
    caller_features,
    cluster_callers,
    heuristic_suspicious,
    isolation_anomalies,
    forecast_calls_per_day,
    generate_nl_most_frequent,
    generate_nl_hourly,
    generate_nl_forecast,
    generate_nl_heuristic,
    generate_nl_ai,
    generate_nl_clustering,
    normalize_device_props,
    parse_battery,
    extract_potential_owner_name,
)

# forensics imports
from forensics import (
    analyze_critical_window,
    detect_activity_bursts,
    build_contact_network,
    get_network_metrics,
    identify_key_contacts,
    detect_burner_phones,
    analyze_contact_relationships,
    detect_behavioral_changes,
    find_repeated_patterns,
    generate_suspect_profile,
    analyze_operational_security,
    reconstruct_timeline,
    detect_suspicious_sms,
    detect_suspicious_apps,
    analyze_system_security_logs,
    detect_network_anomalies,
    analyze_account_risks,
    parse_account_details,
    parse_wifi_profiles,
    analyze_bluetooth_pairings,
    analyze_browser_domains,
    parse_app_usage_stats,
    parse_network_data_usage,
    detect_usage_anomaly_alerts,
)

# report generator imports
from report_generator import (
    generate_comprehensive_report,
    generate_executive_summary,
    generate_finding_summary,
    generate_pdf_report,
)

# forensic Q&A imports
from forensic_qa import answer_forensic_question

# forensic advanced analysis imports
from forensic_advanced_analysis import (
    build_communication_network,
    calculate_network_metrics,
    create_interactive_network_graph,
    calculate_contact_risk_scores,
    create_timeline_view,
    cross_source_correlation,
    analyze_communication_patterns,
    detect_behavioral_anomalies
)

# forensic visualizations imports
from forensic_visualizations import (
    create_timeline_chart,
    create_call_type_distribution,
    create_hourly_activity_chart,
    create_duration_histogram,
    create_top_contacts_chart,
    create_behavioral_heatmap,
    create_burner_phone_chart,
    create_sms_activity_chart,
    create_top_sms_contacts_chart,
    create_browser_activity_chart,
    create_app_usage_chart,
    create_calendar_distribution_chart,
    create_sms_hourly_chart,
    create_sms_length_dist,
    create_app_category_chart,
    create_log_intensity_chart,
    create_browser_domain_pie,
    create_wifi_frequency_chart,
    create_bluetooth_category_chart,
    create_data_usage_bar,
    create_app_foreground_pie,
    create_tx_rx_scatter,
    create_account_distribution_pie,
)

# forensic extractors imports
from forensic_extractors import (
    fetch_sms_raw, fetch_sms_inbox, fetch_sms_sent,
    fetch_contacts_full, fetch_contacts_emails,
    fetch_browser_bookmarks, fetch_browser_searches,
    fetch_calendar_events, fetch_installed_packages,
    fetch_app_usage_stats, fetch_wifi_networks,
    fetch_media_images, fetch_accounts, fetch_owner_profile,
    fetch_mms_raw, fetch_logcat, fetch_notifications, fetch_network_stats,
    parse_sms, parse_installed_packages, parse_calendar_events
)

# ---------- Config ----------
APP_VERSION = "v1.0.0-PRO"
AUTHOR = "Aditya Mohan Srivastava"
st.set_page_config(page_title="Android Forensic Auditor", layout="wide")
plt.rcParams.update({"figure.max_open_warning": 0})

# ---------- Authentication System ----------
def _get_secret(name):
    value = os.environ.get(name)
    if value:
        return value
    try:
        return st.secrets.get(name)
    except Exception:
        return None


def check_password():
    """Returns True if the user had the correct password."""
    def password_entered():
        """Checks whether a password entered by the user is correct."""
        if (
            st.session_state["username"] == _get_secret("APP_USERNAME")
            and st.session_state["password"] == _get_secret("APP_PASSWORD")
        ):
            st.session_state["password_correct"] = True
            del st.session_state["password"]  # don't store password
            del st.session_state["username"]
        else:
            st.session_state["password_correct"] = False

    if "password_correct" not in st.session_state:
        # First run, show inputs for username and password.
        st.markdown("<h1 style='text-align: center;'>Android Forensic Auditor</h1>", unsafe_allow_html=True)
        st.markdown("<p style='text-align: center;'>Please enter your investigator credentials to access the Android Forensic Auditor.</p>", unsafe_allow_html=True)
        
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            with st.form("login_form"):
                st.text_input("Investigator UserID", key="username")
                st.text_input("Password", type="password", key="password")
                st.form_submit_button("Authenticate", on_click=password_entered)
        
        if "password_correct" in st.session_state and not st.session_state["password_correct"]:
            st.error("User not known or password incorrect")
        return False
    elif not st.session_state["password_correct"]:
        # Password not correct, show input + error.
        st.markdown("<h1 style='text-align: center;'>Android Forensic Auditor</h1>", unsafe_allow_html=True)
        col1, col2, col3 = st.columns([1, 2, 1])
        with col2:
            with st.form("login_form"):
                st.text_input("Investigator UserID", key="username")
                st.text_input("Password", type="password", key="password")
                st.form_submit_button("Authenticate", on_click=password_entered)
            st.error("User not known or password incorrect")
        return False
    else:
        # Password correct.
        return True

if not check_password():
    st.stop()  # Do not continue if not authenticated

# ---------- Small UI helpers ----------
def battery_label(level):
    if level is None:
        return "Unknown"
    if level >= 80:
        return "Battery: Good"
    if level >= 40:
        return "Battery: Moderate"
    return "Battery: Low"

def safe_format_dt(d):
    return d.strftime("%Y-%m-%d %H:%M:%S") if pd.notna(d) else ""

def format_number_with_name(row):
    """Format phone number with saved name if available."""
    if pd.notna(row.get("saved_name")) and row.get("saved_name"):
        return f"{row['saved_name']} ({row['number']})"
    return row['number']


def show_app_info():
    st.markdown(
        f"""
### Android Forensic Auditor — &nbsp; <small>{APP_VERSION}</small>

**Purpose:** Comprehensive forensic acquisition and multi-source analysis for Android devices.
It reconstructs digital footprints by correlating call logs, SMS, browsing history, app usage, network environments, and account ecosystems.

**Forensic Capabilities**
- Deep behavioral analysis of communications (Calls & SMS).
- Technical environment mapping (WiFi, Bluetooth, Browser Intent).
- Stealth activity detection (Exfiltration outliers, Nighttime usage, Battery Vampires).
- Automated Suspect Profiling and professional PDF reporting.

> **Note:** Built for analysis & research. Use responsibly.


**Important**
- Only run on devices you own or with explicit permission. The app reads sensitive forensic artifacts.  
- USB debugging must be enabled and the device should be authorized for ADB on this machine.

**Supported Devices**
This application works with **any Android smartphone** that supports:

- **USB Debugging** enabled (Developer Options)  
- **ADB authorization** on your PC  
- **Standard Android Call Log provider access** (`content://call_log/calls`)  
- **Single-SIM, Dual-SIM, and eSIM devices**  
- **Both USB cable mode and Wireless ADB (ADB over Wi-Fi)**

- Compatible Brands (tested or generally supported)
- Xiaomi / Redmi / POCO  
- Samsung (OneUI)  
- OnePlus / Nord (OxygenOS)  
- Realme / Oppo / Vivo (ColorOS / FuntouchOS)  
- Motorola  
- Google Pixel  
- Nokia, ASUS, Lenovo and most stock Android OEMs  

> **Note:** A few OEMs may block call-log access for privacy.  
If extraction returns *0 rows*, your ROM likely restricts the provider.



**Supported Android Versions**

Fully Supported  
- **Android 8 (Oreo) → Android 14**  
  Most stable and consistent call log schema. Works without root.


**Root Requirements**
- **Root is NOT required** for most Android devices.  
- **Root MAY be required** if:
  - Your OEM blocks call log provider access  
  - SELinux restrictions prevent ADB querying  
  - Privacy enhancements hide call logs

"""

,


        unsafe_allow_html=True,
    )


# ---------- Page header ----------
st.title("Android Forensic Auditor")
st.caption(f"Forensic Intelligence Engine v1.0.0-PRO | Investigator: {AUTHOR}")
st.markdown("---")

# ---------- Sidebar: Controls & Device Info ----------
st.sidebar.header("Secure Session")
if st.sidebar.button("Logout"):
    del st.session_state["password_correct"]
    st.rerun()

st.sidebar.markdown("---")
st.sidebar.header("Controls & Device Info")

# ADB / device check
if st.sidebar.button("Check Device"):
    try:
        out = adb_devices()
        st.sidebar.code(out)
        lines = [l.strip() for l in out.splitlines() if l.strip()]
        detected = any("\tdevice" in l or l.endswith("device") for l in lines[1:]) if len(lines) > 1 else False
        if detected:
            st.sidebar.success("Device detected and authorized.")
        else:
            st.sidebar.warning("No authorized device found. Enable USB debugging and accept on phone.")
    except Exception as e:
        st.sidebar.error(str(e))

# Fetch device info
if st.sidebar.button("Fetch Device Info"):
    try:
        st.session_state["props_raw"] = fetch_device_props()
        st.session_state["battery_raw"] = fetch_battery()
        st.session_state["meminfo_raw"] = fetch_meminfo()
        st.session_state["uptime_raw"] = fetch_uptime()
        st.sidebar.success("Device info fetched.")
    except Exception as e:
        st.sidebar.error(str(e))

# Compact device summary UI
if "props_raw" in st.session_state:
    props = normalize_device_props(st.session_state["props_raw"])
    model = props.get("ro.product.model", props.get("ro.product.device", "Unknown"))
    brand = props.get("ro.product.brand", props.get("ro.product.manufacturer", ""))
    android_ver = props.get("ro.build.version.release", "")
    sdk = props.get("ro.build.version.sdk", "")

    st.sidebar.markdown("### Device Information")
    a, b = st.sidebar.columns([2, 1])
    a.write(f"**{brand} {model}**")
    b.caption(f"Android {android_ver}\nSDK {sdk}")

    # uptime
    uptime_txt = st.session_state.get("uptime_raw", "")
    if uptime_txt:
        st.sidebar.metric("Uptime", uptime_txt.split("\n")[0])

    # battery parse & display
    battery_raw = st.session_state.get("battery_raw", "")
    battery = {}
    if battery_raw:
        for line in battery_raw.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                battery[k.strip()] = v.strip()
    level = None
    for key in ("level", "Battery Level", "batteryLevel"):
        if key in battery:
            try:
                level = int("".join(ch for ch in battery[key] if ch.isdigit()))
            except Exception:
                level = None
            break

    if level is not None:
        st.sidebar.metric("Battery", f"{level}%")
        st.sidebar.progress(min(max(level, 0), 100))
        st.sidebar.write(battery_label(level))
    else:
        if battery_raw:
            st.sidebar.caption("Battery info available")

    # health & simple memory snippet
    health = battery.get("health") or battery.get("Health") or battery.get("status")
    if health:
        st.sidebar.write(f"Health: {health}")


st.sidebar.markdown("---")
st.sidebar.header("Extraction & Analysis")

# Fetch contacts button
if st.sidebar.button("Fetch Contacts"):
    try:
        contacts_raw = fetch_contacts_raw()
        st.session_state["contacts_raw"] = contacts_raw  # Save for debugging
        
        # Parse the raw data to see what fields we got
        rows = parse_content_query(contacts_raw)
        if rows:
            st.sidebar.info(f"Fetched {len(rows)} contact data rows")
            
            # Show sample raw row to see available fields
            if rows:
                with st.sidebar.expander("Debug: First contact row fields"):
                    for key, value in rows[0].items():
                        st.caption(f"**{key}**: {value[:50] if len(str(value)) > 50 else value}")
        
        contacts_map = parse_contacts(contacts_raw)
        st.session_state["contacts_map"] = contacts_map
        
        if contacts_map:
            st.sidebar.success(f"Fetched {len(contacts_map)} contacts.")
            # Show sample for debugging
            sample_items = list(contacts_map.items())[:5]
            if sample_items:
                st.sidebar.markdown("**Sample contacts (normalized):**")
                for num, name in sample_items:
                    st.sidebar.caption(f"{name}: `{num}`")
        else:
            st.sidebar.warning("No contacts parsed. Checking raw data...")
            # Show raw output for debugging
            if contacts_raw:
                with st.sidebar.expander("Show raw contacts data (first 1000 chars)"):
                    st.code(contacts_raw[:1000])
                if rows:
                    st.sidebar.error(f"Found {len(rows)} rows but failed to extract name+number pairs")
                else:
                    st.sidebar.error("No rows parsed from raw data")
    except Exception as e:
        st.sidebar.error(f"Contact fetch failed: {e}")
        import traceback
        st.sidebar.code(traceback.format_exc())

if st.sidebar.button("Extract Call Logs"):
    try:
        raw = fetch_call_log_raw()
        st.session_state["raw_output"] = raw
        st.sidebar.success("Raw output fetched and cached.")
    except Exception as e:
        st.sidebar.error(f"Extraction failed: {e}")

if st.sidebar.button("Parse & Analyze"):
    try:
        raw = st.session_state.get("raw_output")
        if raw is None:
            raw = fetch_call_log_raw()
            st.session_state["raw_output"] = raw
        rows = parse_content_query(raw)
        df = normalize_dataframe(rows)
        
        # Names are already extracted from call log itself (df["name"])
        # Now try to enrich with contacts if available
        if "contacts_map" in st.session_state:
            contacts_map = st.session_state["contacts_map"]
            # For numbers without names from call log, try to get from contacts
            df["contact_name"] = df["number"].map(contacts_map).fillna("")
            # Use call log name first, fallback to contact name
            df["saved_name"] = df["name"].fillna(df["contact_name"]).fillna("")
            df = df.drop(columns=["contact_name"])
            
            # Debug: show matching stats
            from_log = (df["name"].notna() & (df["name"] != "")).sum()
            from_contacts = (df["saved_name"] != "") & (df["name"].isna() | (df["name"] == ""))
            from_contacts_count = from_contacts.sum()
            total_named = (df["saved_name"] != "").sum()
            
            st.sidebar.success(f"Parsed {len(df)} records.")
            st.sidebar.info(f"Names: {total_named} total ({from_log} from call log, {from_contacts_count} from contacts)")
            
            # Show sample normalized numbers
            sample_nums = df.head(5)[["number", "name", "saved_name"]].to_dict('records')
            with st.sidebar.expander("Debug: Sample name matching"):
                for item in sample_nums:
                    log_name = item.get('name', '')
                    final_name = item.get('saved_name', '')
                    num = item.get('number', '')
                    st.caption(f"`{num}` → {final_name} (log: {log_name})")
        else:
            # Just use names from call log
            df["saved_name"] = df["name"].fillna("")
            from_log = (df["saved_name"] != "").sum()
            st.sidebar.success(f"Parsed {len(df)} records.")
            st.sidebar.info(f"Names: {from_log} from call log")
            st.sidebar.warning("No contacts loaded. Using names from call log only.")
        
        # Drop the intermediate 'name' column
        df = df.drop(columns=["name"], errors='ignore')
        
        st.session_state["calls_df"] = df
    except Exception as e:
        st.sidebar.error(f"Parse failed: {e}")
        import traceback
        st.sidebar.code(traceback.format_exc())

st.sidebar.markdown("---")
st.sidebar.header("Forensic Acquisition")

# New: Full Acquisition Button
if st.sidebar.button("Run Full Forensic Acquisition", type="primary"):
    with st.status("Performing full forensic acquisition...") as status:
        try:
            steps = [
                ("SMS Messages", fetch_sms_raw, "sms_raw", parse_sms, "sms_data"),
                ("Browser History", lambda: (fetch_browser_bookmarks(), fetch_browser_searches()), ("browser_bookmarks", "browser_searches"), None, None),
                ("Calendar Events", fetch_calendar_events, "calendar_raw", parse_calendar_events, "calendar_events"),
                ("Installed Apps", fetch_installed_packages, "apps_raw", parse_installed_packages, "apps_data"),
                ("WiFi Networks", fetch_wifi_networks, "wifi_raw", None, None),
                ("Accounts", fetch_accounts, "accounts_raw", None, None),
                ("MMS Messages", fetch_mms_raw, "mms_raw", None, None),
                ("Media Metadata", fetch_media_images, "media_images", None, None),
                ("Usage Stats", fetch_app_usage_stats, "app_usage_raw", None, None),
                ("Logs & Notifs", lambda: (fetch_logcat(), fetch_notifications()), ("logcat_raw", "notifications_raw"), None, None),
                ("Network Stats", fetch_network_stats, "netstats_raw", None, None),
                ("Owner Profile", fetch_owner_profile, "profile_raw", None, None)
            ]
            
            progress_bar = st.progress(0)
            for i, (name, fetch_fn, state_key, parse_fn, parse_key) in enumerate(steps):
                try:
                    st.write(f"Extracting {name}...")
                    result = fetch_fn()
                    
                    # Handle multiple return values (tuple)
                    if isinstance(state_key, tuple):
                        for j, k in enumerate(state_key):
                            st.session_state[k] = result[j]
                    else:
                        st.session_state[state_key] = result
                    
                    # Parsing
                    if parse_fn and result:
                        st.session_state[parse_key] = parse_fn(result if not isinstance(result, tuple) else result[0])
                    
                    st.write(f"✓ {name} extracted successfully")
                except Exception as e:
                    st.warning(f"⚠ {name} extraction failed: {str(e)}")
                    # Continue with other extractions
                
                progress_bar.progress((i + 1) / len(steps))
                
            status.update(label="Full acquisition complete!", state="complete")
            st.sidebar.success("Success: All forensic data acquired.")
        except Exception as e:
            status.update(label=f"Acquisition failed: {e}", state="error")
            st.sidebar.error(f"Error: {e}")

st.sidebar.markdown("### Individual Extraction")

# SMS/MMS Extraction
if st.sidebar.button("Extract SMS Messages"):
    try:
        sms_raw = fetch_sms_raw()
        st.session_state["sms_raw"] = sms_raw
        sms_data = parse_sms(sms_raw)
        st.session_state["sms_data"] = sms_data
        st.sidebar.success(f"Extracted {len(sms_data)} SMS messages")
    except Exception as e:
        st.sidebar.error(f"SMS extraction failed: {e}")

# Browser History
if st.sidebar.button("Extract Browser History"):
    try:
        bookmarks = fetch_browser_bookmarks()
        searches = fetch_browser_searches()
        st.session_state["browser_bookmarks"] = bookmarks
        st.session_state["browser_searches"] = searches
        st.sidebar.success("Browser history extracted")
    except Exception as e:
        st.sidebar.error(f"Browser extraction failed: {e}")

# Calendar Events
if st.sidebar.button("Extract Calendar Events"):
    try:
        events_raw = fetch_calendar_events()
        st.session_state["calendar_raw"] = events_raw
        events_data = parse_calendar_events(events_raw)
        st.session_state["calendar_events"] = events_data
        st.sidebar.success(f"Extracted {len(events_data)} calendar events")
    except Exception as e:
        st.sidebar.error(f"Calendar extraction failed: {e}")

# Installed Apps
if st.sidebar.button("Extract Installed Apps"):
    try:
        apps_raw = fetch_installed_packages()
        st.session_state["apps_raw"] = apps_raw
        apps_data = parse_installed_packages(apps_raw)
        st.session_state["apps_data"] = apps_data
        st.sidebar.success(f"Found {len(apps_data)} installed apps")
    except Exception as e:
        st.sidebar.error(f"App extraction failed: {e}")

# WiFi Networks
if st.sidebar.button("Extract WiFi Networks"):
    try:
        wifi_raw = fetch_wifi_networks()
        st.session_state["wifi_raw"] = wifi_raw
        st.sidebar.success("WiFi networks extracted")
    except Exception as e:
        st.sidebar.error(f"WiFi extraction failed: {e}")

# Accounts
if st.sidebar.button("Extract Account Info"):
    try:
        accounts_raw = fetch_accounts()
        st.session_state["accounts_raw"] = accounts_raw
        st.sidebar.success("Account information extracted")
    except Exception as e:
        st.sidebar.error(f"Account extraction failed: {e}")

# MMS
if st.sidebar.button("Extract MMS Messages"):
    try:
        mms_raw = fetch_mms_raw()
        st.session_state["mms_raw"] = mms_raw
        st.sidebar.success("MMS messages extracted")
    except Exception as e:
        st.sidebar.error(f"MMS extraction failed: {e}")

# Media Metadata
if st.sidebar.button("Extract Media Metadata"):
    try:
        images = fetch_media_images()
        st.session_state["media_images"] = images
        st.sidebar.success("Media metadata extracted")
    except Exception as e:
        st.sidebar.error(f"Media extraction failed: {e}")

# App Usage Stats
if st.sidebar.button("Extract App Usage Stats"):
    try:
        usage = fetch_app_usage_stats()
        st.session_state["app_usage_raw"] = usage
        st.sidebar.success("App usage stats extracted")
    except Exception as e:
        st.sidebar.error(f"Usage stats extraction failed: {e}")

# System Logs & Notifications
if st.sidebar.button("Extract Logs & Notifications"):
    try:
        logs = fetch_logcat()
        notifs = fetch_notifications()
        st.session_state["logcat_raw"] = logs
        st.session_state["notifications_raw"] = notifs
        st.sidebar.success("Logs and notifications extracted")
    except Exception as e:
        st.sidebar.error(f"Logs extraction failed: {e}")

# Network Stats
if st.sidebar.button("Extract Network Stats"):
    try:
        netstats = fetch_network_stats()
        st.session_state["netstats_raw"] = netstats
        st.sidebar.success("Network statistics extracted")
    except Exception as e:
        st.sidebar.error(f"Network stats extraction failed: {e}")




# ---------- If no parsed data: stop ----------
if "calls_df" not in st.session_state:
    st.info("No parsed logs in session. Use the sidebar: Extract -> Parse & Analyze.")
    show_app_info()
    st.stop()

# ---------- Main area: Tabs ----------
df_all = st.session_state["calls_df"]

# filter widgets (Date & type)
st.sidebar.markdown("### Date & Type filters")
min_date = df_all["date"].min() if not df_all["date"].isna().all() else None
max_date = df_all["date"].max() if not df_all["date"].isna().all() else None
date_range = st.sidebar.date_input("Date range", value=(min_date, max_date))
call_types = st.sidebar.multiselect(
    "Call types",
    options=df_all["call_type"].unique().tolist(),
    default=df_all["call_type"].unique().tolist(),
)

df = df_all.copy()
if isinstance(date_range, tuple) and len(date_range) == 2 and all(date_range):
    start, end = date_range
    df = df[(df["date"] >= start) & (df["date"] <= end)]
if call_types:
    df = df[df["call_type"].isin(call_types)]

# Initialize AI configuration variables
cluster_k = st.session_state.get('cluster_k', 3)
forecast_days = st.session_state.get('forecast_days', 7)
contamination = st.session_state.get('contamination', 0.05)

# ---------- UNIVERSAL FORENSIC DATA LAYER ----------
# Prepare all data sources globally for Overview/Analytics/Alerts
sms_df = pd.DataFrame(st.session_state.get("sms_data", []))
if not sms_df.empty:
    sms_df['datetime'] = pd.to_datetime(pd.to_numeric(sms_df['date']), unit='ms', errors='coerce')
    if "contacts_map" in st.session_state:
        from helper import normalize_phone_number
        sms_df['contact_name'] = sms_df['address'].apply(lambda x: st.session_state["contacts_map"].get(normalize_phone_number(x), ""))

suspicious_apps_df = detect_suspicious_apps(st.session_state.get("installed_packages", []))
security_logs = analyze_system_security_logs(st.session_state.get("logcat_raw", ""))
network_anomalies = detect_network_anomalies(st.session_state.get("wifi_raw", ""), st.session_state.get("browser_searches", ""))
app_usage_df = parse_app_usage_stats(st.session_state.get("app_usage_raw", ""))
net_traffic_df = parse_network_data_usage(st.session_state.get("netstats_raw", ""))
account_risk_findings = analyze_account_risks(st.session_state.get("accounts_raw", ""))
account_inventory_df = parse_account_details(st.session_state.get("accounts_raw", ""))
raw_usage_alerts = detect_usage_anomaly_alerts(
    st.session_state.get("app_usage_raw", ""),
    net_traffic_df,
    st.session_state.get("batterystats_raw", "")
)
suspicious_sms_df = detect_suspicious_sms(sms_df) if not sms_df.empty else pd.DataFrame()

# Consolidated Alerts for Global Dashboard
all_alerts = []
if not suspicious_apps_df.empty: 
    for _, r in suspicious_apps_df.iterrows(): all_alerts.append({'module': 'Apps', 'level': 'Warning', 'msg': f"Suspicious App: {r['package']} (Score: {r['score']})"})
if not suspicious_sms_df.empty: 
    for _, r in suspicious_sms_df.iterrows(): all_alerts.append({'module': 'SMS', 'level': 'Critical', 'msg': f"Suspicious SMS to {r['address']}: {r['reasons']}"})
if network_anomalies: 
    for a in network_anomalies: all_alerts.append({'module': 'Network', 'level': 'Caution', 'msg': a})
if security_logs: 
    for l in security_logs: all_alerts.append({'module': 'System', 'level': 'Security', 'msg': f"{l['category']}: {l['content'][:50]}..."})
if account_risk_findings:
    for f in account_risk_findings: all_alerts.append({'module': 'Identity', 'level': 'Account', 'msg': f"{f['category']}: {f['detail']}"})
if raw_usage_alerts:
    for a in raw_usage_alerts: all_alerts.append({'module': 'Usage', 'level': 'Traffic', 'msg': f"{a['category']}: {a['package']} - {a['details']}"})

tab_overview, tab_analytics, tab_alerts, tab_forensics, tab_communications, tab_system, tab_settings = st.tabs(
    ["Overview", "Analytics", "Alerts", "Forensics", "Communications", "System", "Settings"]
)

# ---------------- Overview Tab ----------------
with tab_overview:
    st.subheader("Forensic Auditor Overview")
    
    # Universal KPI Matrix
    k_sms = len(sms_df) if not sms_df.empty else 0
    k_apps = len(st.session_state.get("installed_packages", []))
    k_net = len(network_anomalies)
    k_sec = len(security_logs)
    
    m1, m2, m3, m4, m5 = st.columns(5)
    with m1: st.metric("Total Calls", len(df))
    with m2: st.metric("Total SMS", k_sms)
    with m3: st.metric("Apps Extracted", k_apps)
    with m4: st.metric("Account Links", len(account_inventory_df))
    with m5: st.metric("System Alerts", k_sec + k_net + len(all_alerts))

    st.markdown("---")
    
    # Forensic Module Pulse
    st.markdown("### Forensic Module Pulse")
    p1, p2, p3, p4 = st.columns(4)
    with p1:
        st.write("**Communications**")
        st.caption(f"Calls: {len(df)}")
        st.caption(f"SMS: {k_sms}")
        if not suspicious_sms_df.empty: st.markdown(f"**{len(suspicious_sms_df)} Suspicious SMS Flags**")
    with p2:
        st.write("**Software & Apps**")
        st.caption(f"Packages: {k_apps}")
        if not suspicious_apps_df.empty: st.markdown(f"**{len(suspicious_apps_df)} Risky App Flags**")
    with p3:
        st.write("**Technical & Net**")
        st.caption(f"WiFi: {len(network_anomalies)} Logs")
        if raw_usage_alerts: st.markdown(f"**{len(raw_usage_alerts)} Traffic Anomaly Flags**")
    with p4:
        st.write("**Identity & System**")
        st.caption(f"Accounts: {len(account_inventory_df)}")
        if security_logs: st.markdown(f"**{len(security_logs)} Security Event Flags**")

    st.markdown("---")
    st.markdown("### Recent Investigation Activity")
    colA, colB = st.columns([2, 1])
    with colA:
        st.write("Recent calls (top 10)")
        recent = df.head(10).copy()
        recent["datetime"] = recent["datetime"].apply(safe_format_dt)
        recent["contact"] = recent.apply(format_number_with_name, axis=1)
        display_cols = ["datetime", "contact", "call_type", "duration"]
        if "saved_name" not in recent.columns:
            display_cols = ["datetime", "number", "call_type", "duration"]
            st.table(recent[display_cols])
        else:
            st.table(recent[display_cols])
    with colB:
        st.write("Top callers")
        top = most_frequent(df, top_n=10)
        # Add saved names to top callers
        if "contacts_map" in st.session_state and not top.empty:
            contacts_map = st.session_state["contacts_map"]
            top["saved_name"] = top["number"].map(contacts_map).fillna("")
            top["contact"] = top.apply(
                lambda row: f"{row['saved_name']} ({row['number']})" if row['saved_name'] else row['number'],
                axis=1
            )
            st.table(top[["contact", "count"]])
        else:
            st.table(top)
        st.info(generate_nl_most_frequent(top))

    st.markdown("### About this application")
    st.info(
        """
- **Extractor**: uses `adb` (platform-tools) to read the Android call log provider.  
- **Privacy**: data remains local unless you export it. Use only on devices you own or have permission for.  
- **Notes**: For screenshots, contacts or other advanced probes you may need additional permissions or root on device.
"""
    )

# ---------------- Analytics Tab ----------------
with tab_analytics:
    st.subheader("Universal Forensic Analytics")

    # Integrated Communication Pulse (Calls + SMS)
    if not df.empty or not sms_df.empty:
        st.markdown("#### Integrated Communication Pulse (Calls + SMS)")
        pulse_data = []
        if not df.empty:
            c_daily = df.groupby(df['datetime'].dt.date).size().reset_index(name='count')
            c_daily['source'] = 'Calls'
            pulse_data.append(c_daily)
        if not sms_df.empty:
            s_daily = sms_df.groupby(sms_df['datetime'].dt.date).size().reset_index(name='count')
            s_daily['source'] = 'SMS'
            pulse_data.append(s_daily)
        
        if pulse_data:
            pulse_df = pd.concat(pulse_data)
            fig_pulse = px.line(pulse_df, x='datetime', y='count', color='source', markers=True,
                               title="Daily Communication Volume Correlation",
                               labels={'datetime': 'Date', 'count': 'Quantity'},
                               color_discrete_map={'Calls': '#007bff', 'SMS': '#28a745'})
            fig_pulse.update_layout(height=450, hovermode='x unified')
            st.plotly_chart(fig_pulse, use_container_width=True)
            st.markdown("---")
    
    st.subheader("Call Log Deep Analytics")

    # Calls by hour
    st.markdown("#### Calls by hour")
    hour_pivot = calls_by_hour(df)
    st.dataframe(hour_pivot)
    if not df.empty:
        total_by_hour = df.groupby("hour").size().reindex(range(0, 24), fill_value=0)
        fig1 = go.Figure(data=[go.Bar(
            x=list(range(24)),
            y=total_by_hour.values,
            marker_color='#007bff',
            text=total_by_hour.values,
            textposition='auto'
        )])
        fig1.update_layout(
            title="Total calls by hour",
            xaxis_title="Hour (0-23)",
            yaxis_title="Count",
            height=400,
            hovermode='x unified'
        )
        st.plotly_chart(fig1, use_container_width=True)

    # Heatmap
    st.markdown("#### Heatmap (hour × weekday)")
    heat = calls_heatmap(df)
    if not heat.empty:
        day_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        fig2 = go.Figure(data=go.Heatmap(
            z=heat.values,
            x=day_names,
            y=list(heat.index),
            colorscale='Blues',
            hoverongaps=False
        ))
        fig2.update_layout(
            title="Calls heatmap (hour × weekday)",
            xaxis_title="Weekday",
            yaxis_title="Hour",
            height=500
        )
        st.plotly_chart(fig2, use_container_width=True)
    else:
        st.info("No heatmap data.")

    # Calls per day + forecast
    st.markdown("#### Calls per day & forecast")
    series = calls_per_day(df)
    if not series.empty:
        fig3 = go.Figure()
        fig3.add_trace(go.Scatter(
            x=series["date"],
            y=series["count"],
            mode='lines+markers',
            name='Actual Calls',
            line=dict(color='#007bff', width=2),
            marker=dict(size=6)
        ))
        fig3.update_layout(
            title="Calls per day",
            xaxis_title="Date",
            yaxis_title="Calls",
            height=400,
            hovermode='x unified'
        )
        st.plotly_chart(fig3, use_container_width=True)

        fc = forecast_calls_per_day(series, days_ahead=forecast_days)
        st.info(generate_nl_forecast(fc, days=forecast_days))

        if not fc.empty:
            figf = go.Figure()
            # Separate historical and forecast data
            historical_count = len(series)
            figf.add_trace(go.Scatter(
                x=fc["date"][:historical_count],
                y=fc["count"][:historical_count],
                mode='lines+markers',
                name='Historical',
                line=dict(color='#007bff', width=2),
                marker=dict(size=6)
            ))
            figf.add_trace(go.Scatter(
                x=fc["date"][historical_count-1:],
                y=fc["count"][historical_count-1:],
                mode='lines+markers',
                name='Forecast',
                line=dict(color='#fd7e14', width=2, dash='dash'),
                marker=dict(size=6)
            ))
            if "lower" in fc.columns and "upper" in fc.columns:
                figf.add_trace(go.Scatter(
                    x=fc["date"][historical_count-1:],
                    y=fc["upper"][historical_count-1:],
                    mode='lines',
                    name='Upper Bound',
                    line=dict(width=0),
                    showlegend=False
                ))
                figf.add_trace(go.Scatter(
                    x=fc["date"][historical_count-1:],
                    y=fc["lower"][historical_count-1:],
                    mode='lines',
                    name='Confidence Interval',
                    fill='tonexty',
                    fillcolor='rgba(253, 126, 20, 0.2)',
                    line=dict(width=0)
                ))
            figf.update_layout(
                title="Calls per day with forecast",
                xaxis_title="Date",
                yaxis_title="Calls",
                height=400,
                hovermode='x unified'
            )
            st.plotly_chart(figf, use_container_width=True)
    else:
        st.info("No per-day series to show/forecast.")

    # Duration histogram
    st.markdown("#### Duration distribution")
    if not df.empty:
        durations = df["duration_s"].clip(0, 3600)
        fig4 = go.Figure(data=[go.Histogram(
            x=durations,
            nbinsx=30,
            marker_color='#28a745',
            opacity=0.7
        )])
        fig4.update_layout(
            title="Duration distribution",
            xaxis_title="Duration (s) [capped at 3600s]",
            yaxis_title="Count",
            height=400,
            bargap=0.1
        )
        st.plotly_chart(fig4, use_container_width=True)

    # Clustering
    st.markdown("#### Caller clustering")
    agg = caller_features(df)
    if agg.empty:
        st.info("Not enough data to compute caller aggregates / clustering.")
    else:
        clustered = cluster_callers(agg, k=cluster_k)
        clustered_display = clustered.sort_values("total_calls", ascending=False).head(30).copy()
        # Add saved names
        if "contacts_map" in st.session_state:
            contacts_map = st.session_state["contacts_map"]
            clustered_display["saved_name"] = clustered_display["number"].map(contacts_map).fillna("")
            clustered_display["contact"] = clustered_display.apply(
                lambda row: f"{row['saved_name']} ({row['number']})" if row['saved_name'] else row['number'],
                axis=1
            )
            display_cols = ["contact", "total_calls", "avg_duration", "total_duration", "missed_calls", "pct_missed", "cluster", "cluster_dist"]
            st.table(clustered_display[display_cols])
        else:
            st.table(clustered_display)
        st.info(generate_nl_clustering(clustered))
        counts = clustered["cluster"].value_counts().sort_index()
        fig6 = go.Figure(data=[go.Bar(
            x=counts.index.astype(str),
            y=counts.values,
            marker_color='#6f42c1',
            text=counts.values,
            textposition='auto'
        )])
        fig6.update_layout(
            title="Callers per cluster",
            xaxis_title="Cluster",
            yaxis_title="Number of callers",
            height=400
        )
        st.plotly_chart(fig6, use_container_width=True)

# ---------------- Alerts Tab ----------------
with tab_alerts:
    st.subheader("Global Forensic Risk Dashboard")
    st.caption("Consolidated alerts across all forensic modules")

    if not all_alerts:
        st.success("No high-priority universal anomalies detected across extraction modules.")
    else:
        st.error(f"### {len(all_alerts)} Critical Anomalies Found")
        
        # Modular Alert Summary
        alert_summary = pd.DataFrame(all_alerts)
        a_cols = st.columns(4)
        with a_cols[0]: st.metric("App Risks", len(alert_summary[alert_summary['module'] == 'Apps']))
        with a_cols[1]: st.metric("SMS Risks", len(alert_summary[alert_summary['module'] == 'SMS']))
        with a_cols[2]: st.metric("Network Risks", len(alert_summary[alert_summary['module'] == 'Network']))
        with a_cols[3]: st.metric("System Risks", len(alert_summary[alert_summary['module'] == 'System']))

        st.dataframe(alert_summary, use_container_width=True)
    
    st.markdown("---")
    st.markdown("### Communication Anomalies (Call Logs)")

    # Heuristic suspicious
    st.markdown("### Heuristic suspicious detections")
    sus = heuristic_suspicious(df)
    if sus.empty:
        st.success("No heuristic suspicious activity detected.")
    else:
        st.warning(f"{len(sus)} heuristic suspicious records flagged.")
        sus_display = sus.copy()
        sus_display["datetime"] = sus_display["datetime"].apply(safe_format_dt)
        # Add saved names
        if "contacts_map" in st.session_state:
            contacts_map = st.session_state["contacts_map"]
            sus_display["saved_name"] = sus_display["number"].map(contacts_map).fillna("")
            sus_display["contact"] = sus_display.apply(
                lambda row: f"{row['saved_name']} ({row['number']})" if row['saved_name'] else row['number'],
                axis=1
            )
            display_cols = ["contact", "datetime", "call_type", "duration_s", "reason", "score"]
            st.dataframe(sus_display[display_cols].head(300))
        else:
            st.dataframe(sus_display.head(300))
        st.info(generate_nl_heuristic(sus))

    # AI anomalies
    st.markdown("### AI anomalies (IsolationForest)")
    anoms = isolation_anomalies(df, contamination=contamination)
    if anoms.empty:
        st.info("No anomalies flagged or not enough data.")
    else:
        st.error(f"{len(anoms)} anomalies flagged by IsolationForest.")
        anoms_display = anoms.copy()
        anoms_display["datetime"] = anoms_display["datetime"].apply(safe_format_dt)
        # Add saved names
        if "contacts_map" in st.session_state:
            contacts_map = st.session_state["contacts_map"]
            anoms_display["saved_name"] = anoms_display["number"].map(contacts_map).fillna("")
            anoms_display["contact"] = anoms_display.apply(
                lambda row: f"{row['saved_name']} ({row['number']})" if row['saved_name'] else row['number'],
                axis=1
            )
            display_cols = ["contact", "datetime", "call_type", "duration_s", "anomaly_score"]
            st.dataframe(anoms_display[display_cols].head(300))
        else:
            st.dataframe(anoms_display.head(300))
        st.info(generate_nl_ai(anoms))

    # Combined risk scoring
    st.markdown("### Combined risk scoring")
    merged = df.copy()
    anomaly_map = {}
    if not anoms.empty:
        anomaly_map = anoms.set_index(["number", "datetime"])["anomaly_score"].to_dict()
    merged["anomaly_score"] = merged.apply(lambda r: float(anomaly_map.get((r["number"], r["datetime"]), 0)), axis=1)
    clustered_map = {}
    if not agg.empty:
        clustered_map = cluster_callers(agg, k=cluster_k).set_index("number")["cluster_dist"].to_dict()
    merged["cluster_dist"] = merged["number"].map(clustered_map).fillna(0)
    merged["heuristic"] = merged.apply(
        lambda r: (1.0 if r["duration_s"] >= 3600 else 0) + (0.5 if pd.notna(r["hour"]) and (0 <= r["hour"] <= 5) and r["duration_s"] > 0 else 0),
        axis=1,
    )
    merged["risk_score"] = merged["anomaly_score"] * 0.6 + merged["cluster_dist"] * 0.2 + merged["heuristic"] * 0.2
    top_risk = merged.sort_values("risk_score", ascending=False).head(200)
    if not top_risk.empty:
        top_risk_display = top_risk.copy()
        top_risk_display["datetime"] = top_risk_display["datetime"].apply(safe_format_dt)
        # Add saved names
        if "contacts_map" in st.session_state:
            contacts_map = st.session_state["contacts_map"]
            top_risk_display["saved_name"] = top_risk_display["number"].map(contacts_map).fillna("")
            top_risk_display["contact"] = top_risk_display.apply(
                lambda row: f"{row['saved_name']} ({row['number']})" if row['saved_name'] else row['number'],
                axis=1
            )
            display_cols = ["contact", "datetime", "call_type", "duration", "anomaly_score", "cluster_dist", "heuristic", "risk_score"]
            st.dataframe(top_risk_display[display_cols].head(200))
        else:
            st.dataframe(top_risk_display[["number", "datetime", "call_type", "duration", "anomaly_score", "cluster_dist", "heuristic", "risk_score"]].head(200))
    else:
        st.info("No high-risk calls found.")

# ---------------- Settings Tab ----------------
with tab_settings:
    st.subheader("Settings & Configuration")
    st.markdown("Configure analysis parameters and AI models")
    
    st.markdown("---")
    st.markdown("### Analysis Parameters")
    
    col_set1, col_set2, col_set3 = st.columns(3)
    
    with col_set1:
        st.markdown("**Clustering Configuration**")
        cluster_k = st.slider(
            "Number of caller clusters (K)",
            min_value=1,
            max_value=8,
            value=st.session_state.get('cluster_k', 3),
            help="Number of groups to categorize callers into based on behavior patterns"
        )
        st.session_state['cluster_k'] = cluster_k
    
    with col_set2:
        st.markdown("**Forecasting Configuration**")
        forecast_days = st.slider(
            "Forecast horizon (days)",
            min_value=3,
            max_value=30,
            value=st.session_state.get('forecast_days', 7),
            help="Number of days ahead to predict call patterns"
        )
        st.session_state['forecast_days'] = forecast_days
    
    with col_set3:
        st.markdown("**Anomaly Detection Configuration**")
        contamination = st.slider(
            "Anomaly contamination rate",
            min_value=0.01,
            max_value=0.2,
            value=st.session_state.get('contamination', 0.05),
            step=0.01,
            help="Expected proportion of outliers in the dataset (lower = stricter detection)"
        )
        st.session_state['contamination'] = contamination
    
    st.markdown("---")
    st.markdown("### About Configuration")
    st.info("""
**Cluster K**: Groups similar calling patterns together. Higher values create more granular groups.

**Forecast Horizon**: Predicts future call activity based on historical patterns. Longer horizons may be less accurate.

**Contamination Rate**: Controls sensitivity of anomaly detection. Lower values flag fewer but more certain anomal

ies.
    """)
    
    st.markdown("---")
    st.markdown("### Data Management")
    
    col_dm1, col_dm2 = st.columns(2)
    with col_dm1:
        if st.button("Clear Session Data"):
            for k in ["raw_output", "calls_df", "contacts_map", "forensic_report", "case_info"]:
                if k in st.session_state:
                    del st.session_state[k]
            st.success("Session cleared.")
    
    with col_dm2:
        if st.button("Clear Device Info"):
            for k in ["props_raw", "battery_raw", "meminfo_raw", "uptime_raw"]:
                if k in st.session_state:
                    del st.session_state[k]
            st.success("Device info cleared.")

# ---------------- Forensics Tab ----------------
with tab_forensics:
    st.subheader("Forensic Investigation Tools")
    st.caption("Advanced analysis for crime scene digital forensics")
    
    if df.empty:
        st.info("No data available for forensic analysis. Extract and parse call logs first.")
    else:
        # Critical Time Window Analysis
        st.markdown("### Critical Time Window Analysis")
        col_date, col_time, col_window = st.columns([2, 1, 1])
        with col_date:
            incident_date = st.date_input("Incident Date", value=datetime.now().date())
        with col_time:
            incident_time = st.time_input("Incident Time", value=datetime.now().time())
        with col_window:
            window_hours = st.slider("Window (hours)", 1, 72, 24)
        
        incident_datetime = datetime.combine(incident_date, incident_time)
        
        if st.button("Analyze Critical Window"):
            analysis = analyze_critical_window(df, incident_datetime, window_hours, window_hours)
            
            if 'before' in analysis:
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(f"**Before ({window_hours}h)**")
                    st.metric("Calls", analysis['before']['count'])
                    st.metric("Unique Numbers", analysis['before']['unique_numbers'])
                with col2:
                    st.markdown(f"**After ({window_hours}h)**")
                    st.metric("Calls", analysis['after']['count'])
                    st.metric("Unique Numbers", analysis['after']['unique_numbers'])
        
        st.markdown("---")
        
        # Burner Phone Detection
        st.markdown("### Burner Phone Detection")
        burners = detect_burner_phones(df, min_calls=5, max_days=7)
        if not burners.empty:
            st.warning(f"{len(burners)} potential burner phones detected")
            st.dataframe(burners[['number', 'total_calls', 'active_days', 'suspicion_score']].head(10))
        else:
            st.success("No burner phones detected")
        
        st.markdown("---")
        
        # Key Contacts
        st.markdown("### Key Contacts Analysis")
        key_contacts = identify_key_contacts(df, top_n=10)
        if not key_contacts.empty:
            st.dataframe(key_contacts[['number', 'call_count', 'total_duration', 'importance_score']])
        
        st.markdown("---")
        
        # Behavioral Changes
        st.markdown("### Behavioral Changes")
        behavior = detect_behavioral_changes(df)
        if 'insufficient_data' not in behavior:
            if behavior.get('change_detected'):
                st.warning("Significant behavioral change detected!")
            if 'first_period' in behavior:
                col1, col2 = st.columns(2)
                with col1:
                    st.metric("Early Calls/Day", f"{behavior['first_period']['calls_per_day']:.1f}")
                with col2:
                    st.metric("Recent Calls/Day", f"{behavior['last_period']['calls_per_day']:.1f}")
        else:
            st.info("Need at least 14 days of data")
        
        st.markdown("---")
        
        # Activity Bursts
        st.markdown("### Activity Bursts")
        bursts = detect_activity_bursts(df, window_minutes=60, threshold=5)
        if not bursts.empty:
            st.success(f"{len(bursts)} activity bursts detected")
            st.dataframe(bursts.head(10))
        else:
            st.info("No unusual activity bursts detected")
        
        st.markdown("---")
        
        # Suspect Profile
        st.markdown("### Suspect Behavioral Profile")
        profile = generate_suspect_profile(df)
        if profile:
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Communications", profile.get('total_communications', 0))
                st.metric("Active Days", profile.get('active_period_days', 0))
            with col2:
                st.metric("Calls/Day", f"{profile.get('communication_frequency', 0):.1f}")
                st.metric("Network Size", profile.get('network_size', 0))
            with col3:
                st.metric("Avg Duration", f"{profile.get('average_call_duration', 0):.0f}s")
                st.metric("Outgoing Ratio", f"{profile.get('outgoing_call_ratio', 0):.1%}")
            
            if profile.get('behavioral_flags'):
                st.warning("**Behavioral Flags:**")
                for flag in profile['behavioral_flags']:
                    st.write(f"• {flag}")
        
        st.markdown("---")
        
        # OPSEC Analysis
        st.markdown("### Operational Security Assessment")
        opsec = analyze_operational_security(df)
        if opsec:
            st.metric("OPSEC Score", f"{opsec.get('opsec_score', 0)}/100")
            st.write(f"**Assessment:** {opsec.get('assessment', 'Unknown')}")
            if opsec.get('indicators'):
                st.write("**Indicators:**")
                for indicator in opsec['indicators']:
                    st.write(f"• {indicator}")
        
        st.markdown("---")
        
        # FORENSIC VISUALIZATIONS
        st.markdown("## Forensic Data Visualizations")
        st.caption("Interactive charts and graphs for visual analysis")
        
        viz_col1, viz_col2 = st.columns(2)
        
        with viz_col1:
            # Timeline Chart
            st.markdown("### Communication Timeline")
            timeline_fig = create_timeline_chart(df)
            if timeline_fig:
                st.plotly_chart(timeline_fig, use_container_width=True)
            
            # Call Type Distribution
            st.markdown("### Call Type Distribution")
            call_type_fig = create_call_type_distribution(df)
            if call_type_fig:
                st.plotly_chart(call_type_fig, use_container_width=True)
            
            # Duration Histogram
            st.markdown("### Call Duration Distribution")
            duration_fig = create_duration_histogram(df)
            if duration_fig:
                st.plotly_chart(duration_fig, use_container_width=True)
            else:
                st.info("No call durations to display")
        
        with viz_col2:
            # Hourly Activity  
            st.markdown("### Hourly Activity Pattern")
            hourly_fig = create_hourly_activity_chart(df)
            if hourly_fig:
                st.plotly_chart(hourly_fig, use_container_width=True)
            
            # Top Contacts
            st.markdown("### Top 10 Contacts")
            contacts_fig = create_top_contacts_chart(df, top_n=10)
            if contacts_fig:
                st.plotly_chart(contacts_fig, use_container_width=True)
            
            # Burner Phone Chart
            st.markdown("### Burner Phone Analysis")
            burners = detect_burner_phones(df)
            if not burners.empty:
                burner_fig = create_burner_phone_chart(burners)
                if burner_fig:
                    st.plotly_chart(burner_fig, use_container_width=True)
            else:
                st.success("No burner phones detected")
        
        # Full-width heatmap
        st.markdown("### Activity Heatmap")
        heatmap_fig = create_behavioral_heatmap(df)
        if heatmap_fig:
            st.plotly_chart(heatmap_fig, use_container_width=True)
        
        st.markdown("---")
        st.markdown("---")
        
        # ========== LAW ENFORCEMENT GRADE ADVANCED ANALYSIS ==========
        st.markdown("## 🔍 Advanced Forensic Analysis")
        st.caption("Law Enforcement Grade - Interactive Network Analysis, Risk Scoring & Timeline Reconstruction")
        
        adv_tab1, adv_tab2, adv_tab3 = st.tabs(["Social Network Analysis", "Contact Risk Scoring", "Timeline Reconstruction"])
        
        with adv_tab1:
            st.markdown("### Interactive Communication Network")
            st.caption("Visualize relationships and identify key contacts - fully interactive graph")
            
            # Build network
            with st.spinner("Building social network graph..."):
                try:
                    # Get SMS data if available
                    sms_df = None
                    if "sms_data" in st.session_state:
                        sms_df = pd.DataFrame(st.session_state["sms_data"])
                    
                    # Build network graph
                    G = build_communication_network(df, sms_df)
                    metrics = calculate_network_metrics(G)
                    
                    # Display metrics
                    net_col1, net_col2, net_col3, net_col4 = st.columns(4)
                    with net_col1:
                        st.metric("Total Contacts", metrics['total_nodes'] - 1)  # Exclude device owner
                    with net_col2:
                        st.metric("Total Communications", metrics['total_edges'])
                    with net_col3:
                        st.metric("Communities Detected", metrics['num_communities'])
                    with net_col4:
                        top_contact = metrics['top_influential'][1] if len(metrics['top_influential']) > 1 else ('N/A', 0)
                        st.metric("Most Influential", str(top_contact[0])[:15])
                    
                    # Display interactive network graph
                    network_fig = create_interactive_network_graph(G, metrics)
                    st.plotly_chart(network_fig, use_container_width=True)
                    
                    # Show top influential contacts
                    st.markdown("#### Key Network Players")
                    influence_col1, influence_col2 = st.columns(2)
                    
                    with influence_col1:
                        st.write("**Most Connected (Degree Centrality)**")
                        for i, (contact, score) in enumerate(metrics['top_influential'][1:6], 1):
                            st.write(f"{i}. {contact} - Score: {score:.3f}")
                    
                    with influence_col2:
                        st.write("**Bridge Contacts (Betweenness)**")
                        for i, (contact, score) in enumerate(metrics['top_bridges'][1:6], 1):
                            st.write(f"{i}. {contact} - Score: {score:.3f}")
                    
                    # Communities
                    if metrics['communities']:
                        with st.expander("View Detected Communities"):
                            for i, community in enumerate(metrics['communities'][:5], 1):
                                st.write(f"**Community {i}:** {', '.join(list(community)[:10])}")
                    
                except Exception as e:
                    st.error(f"Network analysis failed: {str(e)}")
        
        with adv_tab2:
            st.markdown("### Automated Contact Risk Assessment")
            st.caption("AI-powered suspicious contact detection based on behavioral patterns")
            
            with st.spinner("Calculating risk scores..."):
                try:
                    # Get data
                    sms_df = None
                    if "sms_data" in st.session_state:
                        sms_df = pd.DataFrame(st.session_state["sms_data"])
                    
                    apps_df = None
                    if "apps_data" in st.session_state:
                        apps_df = pd.DataFrame(st.session_state["apps_data"])
                    
                    # Calculate risk scores
                    risk_df = calculate_contact_risk_scores(df, sms_df, apps_df)
                    
                    # Display high-risk contacts
                    high_risk = risk_df[risk_df['risk_level'] == 'HIGH']
                    medium_risk = risk_df[risk_df['risk_level'] == 'MEDIUM']
                    low_risk = risk_df[risk_df['risk_level'] == 'LOW']
                    
                    risk_col1, risk_col2, risk_col3 = st.columns(3)
                    with risk_col1:
                        st.metric("HIGH RISK", len(high_risk), delta="Critical", delta_color="inverse")
                    with risk_col2:
                        st.metric("MEDIUM RISK", len(medium_risk), delta="Monitor")
                    with risk_col3:
                        st.metric("LOW RISK", len(low_risk), delta="Normal", delta_color="normal")
                    
                    # Display detailed risk table
                    st.markdown("#### Risk Assessment Results")
                    
                    # Color-code by risk level
                    def highlight_risk(row):
                        if row['risk_level'] == 'HIGH':
                            return ['background-color: #ffcccc; color: black'] * len(row)
                        elif row['risk_level'] == 'MEDIUM':
                            return ['background-color: #fff4cc; color: black'] * len(row)
                        else:
                            return ['background-color: #ccffcc; color: black'] * len(row)
                    
                    styled_risk = risk_df.head(20).style.apply(highlight_risk, axis=1)
                    st.dataframe(styled_risk, use_container_width=True, height=400)
                    
                    # Download option
                    csv = risk_df.to_csv(index=False)
                    st.download_button(
                        label="Download Full Risk Assessment (CSV)",
                        data=csv,
                        file_name=f"contact_risk_assessment_{datetime.now().strftime('%Y%m%d')}.csv",
                        mime="text/csv"
                    )
                    
                except Exception as e:
                    st.error(f"Risk scoring failed: {str(e)}")
        
        with adv_tab3:
            st.markdown("### Unified Timeline Reconstruction")
            st.caption("Chronological view of all communication events - interactive and zoomable")
            
            with st.spinner("Reconstructing timeline..."):
                try:
                    # Get data
                    sms_df = None
                    if "sms_data" in st.session_state:
                        sms_df = pd.DataFrame(st.session_state["sms_data"])
                    
                    # Create timeline
                    timeline_fig, timeline_df = create_timeline_view(df, sms_df)
                    
                    # Display stats
                    time_col1, time_col2, time_col3 = st.columns(3)
                    with time_col1:
                        st.metric("Total Events", len(timeline_df))
                    with time_col2:
                        event_types = timeline_df['type'].value_counts()
                        st.metric("Calls", event_types.get('Call', 0))
                    with time_col3:
                        st.metric("Messages", event_types.get('SMS', 0))
                    
                    # Interactive timeline
                    st.plotly_chart(timeline_fig, use_container_width=True)
                    
                    # Event search
                    st.markdown("#### Event Search & Filter")
                    search_term = st.text_input("Search events (contact number, type, etc.)", "")
                    
                    if search_term:
                        filtered = timeline_df[timeline_df['detail'].str.contains(search_term, case=False, na=False, regex=False)]
                        st.write(f"Found {len(filtered)} matching events:")
                        st.dataframe(filtered, use_container_width=True)
                    else:
                        st.write("**Recent Events:**")
                        st.dataframe(timeline_df.tail(50), use_container_width=True)
                    
                except Exception as e:
                    st.error(f"Timeline reconstruction failed: {str(e)}")
        
        st.markdown("---")
        
        # ========== PHASE 2: CORRELATION & PATTERN ANALYSIS ==========
        st.markdown("## 🕸️ Phase 2: Correlation & Pattern Analysis")
        st.caption("Cross-source correlation engine, pattern detection, and behavioral anomaly analysis")
        
        adv_tab4, adv_tab5, adv_tab6 = st.tabs(["Cross-Source Correlations", "Communication Patterns", "Behavioral Anomalies"])
        
        with adv_tab4:
            st.markdown("### Cross-Source Correlation Matrix")
            st.caption("Find hidden connections across calls, SMS, apps, browser, and WiFi data")
            
            with st.spinner("Analyzing correlations across data sources..."):
                try:
                    # Get all available data sources
                    sms_df = None
                    if "sms_data" in st.session_state:
                        sms_df = pd.DataFrame(st.session_state["sms_data"])
                    
                    apps_df = None
                    if "apps_data" in st.session_state:
                        apps_df = pd.DataFrame(st.session_state["apps_data"])
                    
                    browser_data = st.session_state.get("browser_searches", None)
                    wifi_data = st.session_state.get("wifi_raw", None)
                    
                    # Find correlations
                    corr_df = cross_source_correlation(df, sms_df, apps_df, browser_data, wifi_data)
                    
                    if not corr_df.empty:
                        # Display summary metrics
                        corr_col1, corr_col2, corr_col3 = st.columns(3)
                        with corr_col1:
                            critical = len(corr_df[corr_df['significance'] == 'CRITICAL'])
                            st.metric("CRITICAL", critical, delta="Urgent" if critical > 0 else "None", delta_color="inverse")
                        with corr_col2:
                            high = len(corr_df[corr_df['significance'] == 'HIGH'])
                            st.metric("HIGH", high, delta="Review" if high > 0 else "None")
                        with corr_col3:
                            medium = len(corr_df[corr_df['significance'] == 'MEDIUM'])
                            st.metric("MEDIUM", medium)
                        
                        st.markdown("#### Detected Correlations")
                        
                        # Color code by significance
                        def highlight_significance(row):
                            if row['significance'] == 'CRITICAL':
                                return ['background-color: #ff0000; color: white'] * len(row)
                            elif row['significance'] == 'HIGH':
                                return ['background-color: #ffcccc; color: black'] * len(row)
                            elif row['significance'] == 'MEDIUM':
                                return ['background-color: #fff4cc; color: black'] * len(row)
                            else:
                                return ['color: black'] * len(row)
                        
                        styled_corr = corr_df.style.apply(highlight_significance, axis=1)
                        st.dataframe(styled_corr, use_container_width=True, height=400)
                        
                        # Download option
                        csv = corr_df.to_csv(index=False)
                        st.download_button(
                            label="Download Correlation Report (CSV)",
                            data=csv,
                            file_name=f"cross_source_correlations_{datetime.now().strftime('%Y%m%d')}.csv",
                            mime="text/csv"
                        )
                    else:
                        st.info("No significant correlations detected. Extract more data sources for deeper analysis.")
                    
                except Exception as e:
                    st.error(f"Correlation analysis failed: {str(e)}")
        
        with adv_tab5:
            st.markdown("### Communication Pattern Analysis")
            st.caption("Identify temporal patterns, frequency spikes, and behavioral routines")
            
            with st.spinner("Analyzing communication patterns..."):
                try:
                    # Get SMS data if available
                    sms_df = None
                    if "sms_data" in st.session_state:
                        sms_df = pd.DataFrame(st.session_state["sms_data"])
                    
                    # Analyze patterns
                    patterns, pattern_fig = analyze_communication_patterns(df, sms_df)
                    
                    if patterns:
                        # Display pattern metrics
                        pat_col1, pat_col2, pat_col3, pat_col4 = st.columns(4)
                        with pat_col1:
                            st.metric("Most Active Hour", f"{patterns['most_active_hour']}:00")
                        with pat_col2:
                            st.metric("Most Active Day", patterns['most_active_day'])
                        with pat_col3:
                            st.metric("Frequency Spikes", patterns['spike_days'])
                        with pat_col4:
                            st.metric("Late Night %", f"{patterns['late_night_percentage']:.1f}%")
                        
                        # Show interactive heatmap
                        if pattern_fig:
                            st.plotly_chart(pattern_fig, use_container_width=True)
                        
                        # Show spike dates if any
                        if patterns['spike_dates']:
                            with st.expander("View Frequency Spike Dates"):
                                st.write("**Dates with unusual high activity:**")
                                for date in patterns['spike_dates'][:10]:
                                    st.write(f"• {date}")
                        
                        # Late night activity details
                        if patterns['late_night_count'] > 0:
                            st.warning(f"⚠️ **{patterns['late_night_count']} late-night communications detected** (00:00-05:00)")
                    else:
                        st.info("Insufficient datetime data for pattern analysis.")
                    
                except Exception as e:
                    st.error(f"Pattern analysis failed: {str(e)}")
        
        with adv_tab6:
            st.markdown("### Behavioral Anomaly Detection")
            st.caption("Identify deviations from normal behavior patterns - automatic baseline establishment")
            
            with st.spinner("Detecting behavioral anomalies..."):
                try:
                    # Get SMS data if available
                    sms_df = None
                    if "sms_data" in st.session_state:
                        sms_df = pd.DataFrame(st.session_state["sms_data"])
                    
                    # Detect anomalies
                    anomaly_df, anomaly_fig = detect_behavioral_anomalies(df, sms_df)
                    
                    if not anomaly_df.empty:
                        # Display anomaly metrics by severity
                        anom_col1, anom_col2, anom_col3, anom_col4 = st.columns(4)
                        with anom_col1:
                            critical = len(anomaly_df[anomaly_df['severity'] == 'CRITICAL'])
                            st.metric("CRITICAL", critical, delta_color="inverse")
                        with anom_col2:
                            high = len(anomaly_df[anomaly_df['severity'] == 'HIGH'])
                            st.metric("HIGH", high)
                        with anom_col3:
                            medium = len(anomaly_df[anomaly_df['severity'] == 'MEDIUM'])
                            st.metric("MEDIUM", medium)
                        with anom_col4:
                            low = len(anomaly_df[anomaly_df['severity'] == 'LOW'])
                            st.metric("LOW", low)
                        
                        # Show interactive timeline
                        if anomaly_fig:
                            st.plotly_chart(anomaly_fig, use_container_width=True)
                        
                        # Display top anomalies
                        st.markdown("#### Top Anomalies (Highest Risk Score)")
                        
                        # Color code by severity
                        def highlight_anomaly(row):
                            if row['severity'] == 'CRITICAL':
                                return ['background-color: #ff0000; color: white'] * len(row)
                            elif row['severity'] == 'HIGH':
                                return ['background-color: #ffcccc; color: black'] * len(row)
                            elif row['severity'] == 'MEDIUM':
                                return ['background-color: #fff4cc; color: black'] * len(row)
                            else:
                                return ['background-color: #e0ffe0; color: black'] * len(row)
                        
                        styled_anom = anomaly_df.head(20).style.apply(highlight_anomaly, axis=1)
                        st.dataframe(styled_anom, use_container_width=True, height=400)
                        
                        # Download option
                        csv = anomaly_df.to_csv(index=False)
                        st.download_button(
                            label="Download Anomaly Report (CSV)",
                            data=csv,
                            file_name=f"behavioral_anomalies_{datetime.now().strftime('%Y%m%d')}.csv",
                            mime="text/csv"
                        )
                    else:
                        st.success("✅ No significant behavioral anomalies detected - normal activity patterns.")
                    
                except Exception as e:
                    st.error(f"Anomaly detection failed: {str(e)}")
        
        st.markdown("---")
        st.markdown("---")
        
        # AI REPORT GENERATION
        st.markdown("## Forensic Intelligence Auditor Report")
        st.caption("Generate a professional, multi-source digital forensic investigation report using Gemini AI")
        
        with st.expander("Report Configuration", expanded=True):
            col_r1, col_r2 = st.columns(2)
            with col_r1:
                case_number = st.text_input("Case Number", value=f"CASE-{datetime.now().strftime('%Y%m%d')}")
                investigator = st.text_input("Investigator Name", value="")
            with col_r2:
                # Identify potential owner name if not already set
                suggested_owner = "Unknown"
                if st.session_state.get("profile_raw") or st.session_state.get("accounts_raw"):
                    suggested_owner = extract_potential_owner_name(
                        st.session_state.get("accounts_raw"), 
                        st.session_state.get("profile_raw")
                    )
                
                device_owner = st.text_input("Device Owner/Suspect", value=suggested_owner)
                classification = st.selectbox("Classification", 
                                              ["CONFIDENTIAL", "SECRET", "TOP SECRET", "UNCLASSIFIED"])
        
        if st.button("Generate AI Forensic Report", type="primary"):
            with st.spinner("AI is analyzing data and generating report... This may take 30-60 seconds"):
                try:
                    # Gather all forensic analyses
                    forensic_analyses = {
                        'burner_phones': detect_burner_phones(df),
                        'key_contacts': identify_key_contacts(df),
                        'behavioral_changes': detect_behavioral_changes(df),
                        'activity_bursts': detect_activity_bursts(df),
                        'relationships': analyze_contact_relationships(df),
                        'suspect_profile': generate_suspect_profile(df),
                        'opsec': analyze_operational_security(df)
                    }
                    
                    # Package all acquired data for AI correlation
                    full_forensic_data = {
                        'sms_data': st.session_state.get('sms_data'),
                        'browser_searches': st.session_state.get('browser_searches'),
                        'apps_data': st.session_state.get('apps_data'),
                        'calendar_events': st.session_state.get('calendar_events'),
                        'wifi_raw': st.session_state.get('wifi_raw'),
                        'logcat_raw': st.session_state.get('logcat_raw'),
                        'app_usage_raw': st.session_state.get('app_usage_raw'),
                        'netstats_raw': st.session_state.get('netstats_raw'),
                        'suspicious_sms': detect_suspicious_sms(pd.DataFrame(st.session_state.get('sms_data', []))) if st.session_state.get('sms_data') else None,
                        'suspicious_apps': detect_suspicious_apps(pd.DataFrame(st.session_state.get('apps_data', []))) if st.session_state.get('apps_data') else None,
                        'security_logs': analyze_system_security_logs(st.session_state.get('logcat_raw', "")) if st.session_state.get('logcat_raw') else None,
                        'network_anomalies': detect_network_anomalies(st.session_state.get('wifi_raw', ""), st.session_state.get('browser_searches', "")),
                        'wifi_profiles': parse_wifi_profiles(st.session_state.get("wifi_raw", "")),
                        'bluetooth_pairings': analyze_bluetooth_pairings(st.session_state.get("bluetooth_raw", "")),
                        'browser_categories': analyze_browser_domains(st.session_state.get("browser_searches", "")),
                        'parsed_app_usage': parse_app_usage_stats(st.session_state.get("app_usage_raw", "")),
                        'parsed_net_traffic': parse_network_data_usage(st.session_state.get("netstats_raw", "")),
                        'raw_anomaly_alerts': detect_usage_anomaly_alerts(
                            st.session_state.get("app_usage_raw", ""),
                            parse_network_data_usage(st.session_state.get("netstats_raw", "")),
                            st.session_state.get("batterystats_raw", "")
                        ),
                        'account_findings': analyze_account_risks(st.session_state.get("accounts_raw", "")),
                        'parsed_accounts': parse_account_details(st.session_state.get("accounts_raw", ""))
                    }
                    
                    # Extract device info if available
                    device_info = None
                    if "props_raw" in st.session_state:
                        # ... (device info parsing remains same) ...
                        props = normalize_device_props(st.session_state["props_raw"])
                        battery_raw = st.session_state.get("battery_raw", "")
                        uptime_raw = st.session_state.get("uptime_raw", "")
                        
                        # Parse battery level
                        battery_level = "Unknown"
                        if battery_raw:
                            battery = {}
                            for line in battery_raw.splitlines():
                                if ":" in line:
                                    k, v = line.split(":", 1)
                                    battery[k.strip()] = v.strip()
                            for key in ("level", "Battery Level", "batteryLevel"):
                                if key in battery:
                                    try:
                                        level = int("".join(ch for ch in battery[key] if ch.isdigit()))
                                        battery_level = f"{level}%"
                                    except:
                                        pass
                                    break
                        
                        # Parse uptime
                        uptime = uptime_raw.split("\n")[0] if uptime_raw else "Unknown"
                        
                        device_info = {
                            'model': props.get("ro.product.model", props.get("ro.product.device", "Unknown")),
                            'brand': props.get("ro.product.brand", props.get("ro.product.manufacturer", "Unknown")),
                            'android_version': props.get("ro.build.version.release", "Unknown"),
                            'sdk': props.get("ro.build.version.sdk", "Unknown"),
                            'battery_level': battery_level,
                            'uptime': uptime
                        }
                    
                    # Case metadata
                    case_info = {
                        'case_number': case_number,
                        'investigator': investigator,
                        'device_owner': device_owner,
                        'classification': classification,
                        'analysis_date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                        'app_version': APP_VERSION
                    }
                    
                    # Generate AI report with all available data
                    report_text = generate_comprehensive_report(
                        case_info, df, forensic_analyses, device_info, full_forensic_data
                    )
                    
                    # Store in session for download
                    st.session_state['forensic_report'] = report_text
                    st.session_state['case_info'] = case_info
                    st.session_state['full_forensic_data'] = full_forensic_data
                    
                    st.success("Android Forensic Auditor Report generated!")
                    
                except Exception as e:
                    st.error(f"Report generation failed: {str(e)}")
                    st.info("Make sure the Gemini API key is configured correctly in report_generator.py")
                    import traceback
                    st.code(traceback.format_exc())
        
        # Display report if generated
        if 'forensic_report' in st.session_state:
            st.markdown("---")
            st.markdown("### Generated Report Preview")
            
            # Show report in expandable section with HTML rendering
            with st.expander("View Full Report", expanded=True):
                st.markdown(st.session_state['forensic_report'], unsafe_allow_html=True)
            
            # Download as PDF
            st.markdown("### Download Report")
            if st.button("Generate PDF Report"):
                with st.spinner("Generating PDF with visualizations..."):
                    try:
                        pdf_data = generate_pdf_report(
                            st.session_state['forensic_report'],
                            st.session_state['case_info'],
                            "temp_report.pdf",
                            df=df,  # Pass df for chart generation
                            full_forensic_data=st.session_state.get('full_forensic_data')
                        )
                        
                        st.download_button(
                            label="Download PDF",
                            data=pdf_data,
                            file_name=f"forensic_report_{case_number}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                            mime="application/pdf"
                        )
                        st.success("PDF generated!")
                    except Exception as e:
                        st.error(f"PDF generation failed: {str(e)}")
                        import traceback
                        st.code(traceback.format_exc())
            
            # Executive Summary
            st.markdown("---")
            st.markdown("### Executive Summary")
            if st.button("Generate Executive Summary"):
                with st.spinner("Generating executive summary..."):
                    try:
                        exec_summary = generate_executive_summary(df, st.session_state.get('forensic_analyses', {}))
                        st.info(exec_summary)
                    except Exception as e:
                        st.error(f"Summary generation failed: {str(e)}")
        
        # INTERACTIVE Q&A SECTION
        st.markdown("---")
        st.markdown("## Ask Questions About the Analyzed Data")
        st.caption("AI will answer based strictly on the extracted forensic evidence")
        
        # Initialize conversation history in session state
        if 'qa_history' not in st.session_state:
            st.session_state['qa_history'] = []
        
        # Display conversation history
        if st.session_state['qa_history']:
            with st.expander("View Conversation History", expanded=False):
                for i, qa in enumerate(st.session_state['qa_history']):
                    st.markdown(f"**Q{i+1}:** {qa['question']}")
                    st.info(qa['answer'])
                    st.markdown("---")
        
        # Question input
        question = st.text_area(
            "Your Question",
            height=100,
            placeholder="Example: Who are the most frequent contacts? What apps indicate privacy concerns? When was the most active communication period?",
            key="forensic_question_input"
        )
        
        col_ask, col_clear = st.columns([3, 1])
        
        with col_ask:
            if st.button("Ask Question", type="primary", use_container_width=True):
                if question.strip():
                    with st.spinner("Analyzing data to answer your question..."):
                        try:
                            # Get full forensic data context
                            full_data = st.session_state.get('full_forensic_data', {})
                            
                            # Generate answer
                            answer = answer_forensic_question(
                                question=question,
                                df=df,
                                full_forensic_data=full_data,
                                conversation_history=st.session_state['qa_history']
                            )
                            
                            # Store in history
                            st.session_state['qa_history'].append({
                                'question': question,
                                'answer': answer
                            })
                            
                            # Display answer
                            st.markdown(f"**Your Question:** {question}")
                            st.success(answer)
                            
                        except Exception as e:
                            st.error(f"Failed to answer question: {str(e)}")
                else:
                    st.warning("Please enter a question first.")
        
        with col_clear:
            if st.button("Clear History", use_container_width=True):
                st.session_state['qa_history'] = []
                st.success("Conversation history cleared.")
                st.rerun()
        
        # Show data context helper
        with st.expander("Available Data Context"):
            st.write("**The AI has access to:**")
            context_items = []
            if not df.empty:
                context_items.append(f"✓ {len(df)} call log records")
            if st.session_state.get('sms_data'):
                context_items.append(f"✓ {len(st.session_state['sms_data'])} SMS messages")
            if st.session_state.get('apps_data'):
                context_items.append(f"✓ {len(st.session_state['apps_data'])} installed apps")
            if st.session_state.get('accounts_raw'):
                context_items.append("✓ Account information")
            if st.session_state.get('wifi_raw'):
                context_items.append("✓ WiFi network data")
            if st.session_state.get('browser_searches'):
                context_items.append("✓ Browser search history")
            
            for item in context_items:
                st.write(item)
            
            if not context_items:
                st.write("⚠️ No data extracted yet. Run Full Forensic Acquisition or extract specific data types.")

# ---------------- Communications Tab ----------------
with tab_communications:
    st.subheader("Communications Exploration")
    st.caption("Investigate SMS messages and other communication channels")
    
    if "sms_data" not in st.session_state:
        st.info("No SMS data extracted. Use the sidebar to 'Extract SMS Messages'.")
    else:
        sms_df = pd.DataFrame(st.session_state["sms_data"])
        
        if not sms_df.empty:
            # Convert timestamp
            sms_df['datetime'] = pd.to_datetime(pd.to_numeric(sms_df['date']), unit='ms', errors='coerce')
            
            # Match with contacts if available
            if "contacts_map" in st.session_state:
                cmap = st.session_state["contacts_map"]
                from helper import normalize_phone_number
                sms_df['contact_name'] = sms_df['address'].apply(lambda x: cmap.get(normalize_phone_number(x), ""))
            
            # --- SMS Analytics (Full Width) ---
            st.markdown("### SMS Forensic Analytics")
            
            # Timeline Chart
            sms_time_fig = create_sms_activity_chart(sms_df)
            if sms_time_fig: st.plotly_chart(sms_time_fig, use_container_width=True)
            
            # Distribution Charts in a cleaner row
            ana_col1, ana_col2 = st.columns(2)
            with ana_col1:
                sms_hourly_fig = create_sms_hourly_chart(sms_df)
                if sms_hourly_fig: st.plotly_chart(sms_hourly_fig, use_container_width=True)
                
                sms_contacts_fig = create_top_sms_contacts_chart(sms_df)
                if sms_contacts_fig: st.plotly_chart(sms_contacts_fig, use_container_width=True)
            
            with ana_col2:
                sms_len_fig = create_sms_length_dist(sms_df)
                if sms_len_fig: st.plotly_chart(sms_len_fig, use_container_width=True)
                
                # Placeholder for other analytics
                st.info("Additional forensic patterns being calculated...")
            
            # --- Suspicious SMS Section ---
            st.markdown("---")
            st.markdown("### Forensic Alerts: Suspicious Messages")
            suspicious_sms_df = detect_suspicious_sms(sms_df)
            if not suspicious_sms_df.empty:
                st.warning(f"Detected {len(suspicious_sms_df)} suspicious message indicators.")
                st.dataframe(suspicious_sms_df[['datetime', 'address', 'score', 'reasons', 'body']], use_container_width=True)
            else:
                st.success("No high-risk suspicious SMS patterns detected by heuristics.")
                
            # --- Message Explorer ---
            st.markdown("---")
            st.markdown("### Message Explorer")
            
            col_sms1, col_sms2 = st.columns(2)
            with col_sms1:
                sms_filter = st.text_input("Filter messages (number or text)")
            with col_sms2:
                sms_type = st.multiselect("Message Type", options=["1", "2"], default=["1", "2"], format_func=lambda x: "Inbox" if x=="1" else "Sent")
            
            filtered_sms = sms_df[sms_df['type'].isin(sms_type)]
            if sms_filter:
                filtered_sms = filtered_sms[
                    filtered_sms['address'].str.contains(sms_filter, case=False, na=False) | 
                    filtered_sms['body'].str.contains(sms_filter, case=False, na=False) |
                    filtered_sms.get('contact_name', '').str.contains(sms_filter, case=False, na=False)
                ]
            
            st.write(f"Showing {len(filtered_sms)} messages")
            
            # Prettier display
            for _, row in filtered_sms.head(100).iterrows():
                with st.chat_message("user" if row['type'] == "2" else "assistant"):
                    name_display = row.get('contact_name', '') or row['address']
                    st.write(f"**{name_display}** ({row['datetime']})")
                    st.write(row['body'])
        else:
            st.warning("SMS database appears to be empty.")

# ---------------- System Tab ----------------
with tab_system:
    st.subheader("System Artifacts")
    st.caption("Device configuration, installed apps, and system logs")
    
    sys_tab1, sys_tab2, sys_tab3, sys_tab4, sys_tab5, sys_tab6 = st.tabs(["Apps", "Calendar", "Connectivity", "Media & Stats", "Logs", "Accounts"])
    
    with sys_tab1:
        st.markdown("### Installed Applications")
        if "apps_data" in st.session_state:
            # App Forensics & Visuals
            apps_df = pd.DataFrame(st.session_state["apps_data"])
            suspicious_apps = detect_suspicious_apps(apps_df)
            
            f_col1, f_col2 = st.columns([1, 1])
            with f_col1:
                st.markdown("#### Forensic Interest Apps")
                if not suspicious_apps.empty:
                    st.warning(f"Detected {len(suspicious_apps)} applications of forensic interest.")
                    st.dataframe(suspicious_apps, use_container_width=True)
                else:
                    st.success("No high-risk package names detected.")
            
            with f_col2:
                app_cat_fig = create_app_category_chart(suspicious_apps)
                if app_cat_fig: st.plotly_chart(app_cat_fig, use_container_width=True)

            st.markdown("---")
            st.markdown("#### App Usage Analysis")
            if "app_usage_raw" in st.session_state:
                app_fig = create_app_usage_chart(st.session_state["app_usage_raw"])
                if app_fig: st.plotly_chart(app_fig, use_container_width=True)
            
            st.markdown("#### Package List")
            st.dataframe(apps_df, use_container_width=True)
        else:
            st.info("No app data extracted. Use the sidebar to 'Extract Installed Apps'.")
            
    with sys_tab2:
        st.markdown("### Calendar Events")
        if "calendar_events" in st.session_state:
            cal_df = pd.DataFrame(st.session_state["calendar_events"])
            
            # Calendar Visuals
            st.markdown("#### Event Distribution")
            cal_fig = create_calendar_distribution_chart(cal_df)
            if cal_fig: st.plotly_chart(cal_fig, use_container_width=True)
            
            st.markdown("#### Event List")
            st.dataframe(cal_df, use_container_width=True)
        else:
            st.info("No calendar data extracted. Use sidebar to 'Extract Calendar Events'.")
            
    with sys_tab3:
        st.markdown("### Connectivity & Networks")
        
        # Network Forensics
        net_anomalies = detect_network_anomalies(
            st.session_state.get("wifi_raw", ""), 
            st.session_state.get("browser_searches", "")
        )
        if net_anomalies:
            st.warning("#### Connectivity Forensic Alerts")
            for alert in net_anomalies:
                st.write(f"- {alert}")
            st.markdown("---")

        # Visual Row 1: Browsing
        st.markdown("#### Web Browsing Insights")
        if "browser_searches" in st.session_state:
            domain_df = analyze_browser_domains(st.session_state["browser_searches"])
            b_col1, b_col2 = st.columns(2)
            with b_col1:
                domain_fig = create_browser_domain_pie(domain_df)
                if domain_fig: st.plotly_chart(domain_fig, use_container_width=True)
            with b_col2:
                search_fig = create_browser_activity_chart(st.session_state["browser_searches"])
                if search_fig: st.plotly_chart(search_fig, use_container_width=True)
            
            with st.expander("View Domain Categorization"):
                st.dataframe(domain_df, use_container_width=True)

        st.markdown("---")
        
        # Visual Row 2: WiFi & Bluetooth
        st.markdown("#### Hardware & Network Environments")
        hw_col1, hw_col2 = st.columns(2)
        with hw_col1:
            st.markdown("**WiFi Environments**")
            if "wifi_raw" in st.session_state:
                wifi_profiles_df = parse_wifi_profiles(st.session_state["wifi_raw"])
                wifi_fig = create_wifi_frequency_chart(wifi_profiles_df)
                if wifi_fig: st.plotly_chart(wifi_fig, use_container_width=True)
                st.dataframe(wifi_profiles_df, use_container_width=True)
            else:
                st.info("No WiFi data extracted.")
        
        with hw_col2:
            st.markdown("**Bluetooth Pairings**")
            if "bluetooth_raw" in st.session_state:
                bt_pairings = analyze_bluetooth_pairings(st.session_state["bluetooth_raw"])
                bt_fig = create_bluetooth_category_chart(bt_pairings)
                if bt_fig: st.plotly_chart(bt_fig, use_container_width=True)
                if bt_pairings:
                    st.dataframe(pd.DataFrame(bt_pairings), use_container_width=True)
            else:
                st.info("No Bluetooth data extracted. Use sidebar to 'Extract Bluetooth Devices'.")

        st.markdown("---")
        st.markdown("#### Raw Network Data")
        col_c1, col_c2 = st.columns(2)
        with col_c1:
            if "wifi_raw" in st.session_state:
                st.text_area("WiFi System Dump", st.session_state["wifi_raw"], height=200)
        with col_c2:
            if "browser_searches" in st.session_state:
                st.text_area("Search History Raw", st.session_state["browser_searches"], height=200)
                
    with sys_tab4:
        st.markdown("### Media & Usage Statistics")
        
        # Extreme Anomaly Alerts
        raw_alerts = detect_usage_anomaly_alerts(
            st.session_state.get("app_usage_raw", ""),
            parse_network_data_usage(st.session_state.get("netstats_raw", "")),
            st.session_state.get("batterystats_raw", "")
        )
        if raw_alerts:
            st.error("#### Extreme Digital Anomalies Detected")
            alert_df = pd.DataFrame(raw_alerts)
            st.dataframe(alert_df, use_container_width=True)
            st.markdown("---")

        # Row 1: App Usage Forensics
        st.markdown("#### App Interaction Analysis")
        if "app_usage_raw" in st.session_state:
            usage_df = parse_app_usage_stats(st.session_state["app_usage_raw"])
            u_col1, u_col2 = st.columns(2)
            with u_col1:
                usage_fig = create_app_foreground_pie(usage_df)
                if usage_fig: st.plotly_chart(usage_fig, use_container_width=True)
            with u_col2:
                st.write("**Top Apps by Foreground Time**")
                st.dataframe(usage_df, use_container_width=True)
        else:
            st.info("No detailed usage stats extracted.")

        st.markdown("---")
        
        # Row 2: Network Data Consumption
        st.markdown("#### Network Traffic Forensics")
        if "netstats_raw" in st.session_state:
            net_usage_df = parse_network_data_usage(st.session_state["netstats_raw"])
            n_col1, n_col2 = st.columns(2)
            with n_col1:
                net_fig = create_data_usage_bar(net_usage_df)
                if net_fig: st.plotly_chart(net_fig, use_container_width=True)
            with n_col2:
                st.write("**Data Usage per UID (MB)**")
                st.dataframe(net_usage_df.head(15), use_container_width=True)
            
            st.markdown("#### Tech-Exfiltration Analysis (Tx vs Rx Outliers)")
            tx_rx_fig = create_tx_rx_scatter(net_usage_df)
            if tx_rx_fig: st.plotly_chart(tx_rx_fig, use_container_width=True)
        else:
            st.info("No detailed network stats extracted.")

        st.markdown("---")
        st.markdown("#### Raw Media & Evidence")
        col_m1, col_m2 = st.columns(2)
        with col_m1:
            st.markdown("#### Media Metadata")
            if "media_images" in st.session_state:
                st.text_area("Image Metadata", st.session_state["media_images"], height=200)
            if "mms_raw" in st.session_state:
                st.text_area("MMS Raw Data", st.session_state["mms_raw"], height=200)
            if "media_images" not in st.session_state and "mms_raw" not in st.session_state:
                st.info("No media data extracted.")
        with col_m2:
            st.markdown("#### Raw Usage & Net Dumps")
            if "app_usage_raw" in st.session_state:
                st.text_area("App Usage Stats (Raw)", st.session_state["app_usage_raw"], height=100)
            if "netstats_raw" in st.session_state:
                st.text_area("Network Stats (Raw)", st.session_state["netstats_raw"], height=100)
                
    with sys_tab5:
        st.markdown("### System Logs & Notifications")
        if "logcat_raw" in st.session_state:
            # Log Forensics
            log_findings = analyze_system_security_logs(st.session_state["logcat_raw"])
            if log_findings:
                st.warning("#### Security Log Alerts")
                st.dataframe(pd.DataFrame(log_findings), use_container_width=True)
                
                log_fig = create_log_intensity_chart(log_findings)
                if log_fig: st.plotly_chart(log_fig, use_container_width=True)
                st.markdown("---")

            st.write("**Recent Logcat Entries**")
            st.text_area("Logcat", st.session_state["logcat_raw"], height=300)
        
        if "notifications_raw" in st.session_state:
            st.write("**Recent Notifications**")
            st.text_area("Notifications", st.session_state["notifications_raw"], height=200)
        
        if "logcat_raw" not in st.session_state and "notifications_raw" not in st.session_state:
            st.info("No logs extracted.")
            
    with sys_tab6:
        st.markdown("### Accounts & Identity")
        
        if "accounts_raw" in st.session_state:
            # Deep Account Analytics
            acc_findings = analyze_account_risks(st.session_state["accounts_raw"])
            acc_df = parse_account_details(st.session_state["accounts_raw"])
            
            # Risk Assessment Column
            if acc_findings:
                st.warning("#### Identity Risk Assessment")
                for finding in acc_findings:
                    st.write(f"**{finding['category']}**: {finding['detail']}")
                st.markdown("---")

            # Visualization Row
            st.markdown("#### Identity Footprint")
            acc_col1, acc_col2 = st.columns([1, 2])
            with acc_col1:
                acc_fig = create_account_distribution_pie(acc_df)
                if acc_fig: st.plotly_chart(acc_fig, use_container_width=True)
            with acc_col2:
                st.write("**Account Inventory**")
                st.dataframe(acc_df.sort_values('category'), use_container_width=True)

            st.markdown("---")
            st.write("**Raw Account Dumps**")
            st.text_area("Accounts Raw", st.session_state["accounts_raw"], height=200)
        else:
            st.info("No account data extracted. Use the sidebar to 'Extract Account Info'.")


# ---------------- Settings Tab ----------------
with tab_settings:
    st.subheader("Settings & Export")
    st.markdown("### Export / Session")
    st.download_button("Download parsed CSV (filtered)", data=df.to_csv(index=False).encode("utf-8"), file_name="call_logs_filtered.csv", mime="text/csv")
    st.download_button("Download raw adb output", data=st.session_state.get("raw_output", "").encode("utf-8"), file_name="call_logs_raw.txt", mime="text/plain")

    if st.button("Clear session data (calls, raw)"):
        for k in ["raw_output", "calls_df", "contacts_map", "props_raw", "battery_raw", "meminfo_raw", "uptime_raw"]:
            if k in st.session_state:
                del st.session_state[k]
        st.success("Session cleared. Re-run extraction/analysis as needed.")

    st.markdown("---")
    st.markdown(
        "**Privacy & Legal:** This tool accesses private data on a connected device. Only use on devices you own or have explicit authorization to inspect. Do not share exported data without consent."
    )

# ---------- Footer ----------
st.markdown("---")
st.caption("Built for analysis & research. Use responsibly.")

