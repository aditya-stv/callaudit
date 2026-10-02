# Android Forensic Auditor (CallAudit)

A Streamlit web application for **forensic acquisition and analysis of Android devices over ADB**. It pulls call logs, contacts, SMS/MMS, browser history, calendar, installed apps, Wi‑Fi, accounts, usage statistics, logs and network statistics from a connected phone, then runs statistical, machine‑learning and heuristic analyses on them. It can also produce an **AI‑written investigation report** (Google Gemini online, or a local Ollama model offline), export it as a PDF, and answer investigator questions about the extracted data.

> **Legal notice:** This tool reads highly sensitive personal data. Only use it on devices you own or have explicit, documented authorization to examine. Do not share exported data without consent.

---

## Table of contents

- [Features](#features)
- [How it works](#how-it-works)
- [Project structure](#project-structure)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Running the app](#running-the-app)
- [Usage walkthrough](#usage-walkthrough)
- [The UI tabs](#the-ui-tabs)
- [Analysis methods](#analysis-methods)
- [AI reporting and Q&A](#ai-reporting-and-qa)
- [Device compatibility](#device-compatibility)
- [Module reference](#module-reference)
- [Known limitations](#known-limitations)
- [Author](#author)

---

## Features

**Acquisition (no root required on most devices)**
- Call logs (`content://call_log/calls`) and contacts, with names resolved by phone number
- SMS (inbox/sent/all), MMS, and SMS conversations
- Browser bookmarks and searches
- Calendar events and attendees
- Installed packages, app usage stats, recent apps, battery stats
- Wi‑Fi networks, Bluetooth pairings, network data usage (`netstats`), location dump
- Media metadata (images, video, audio) and downloads
- `logcat` (last 1000 lines), notifications, accounts, owner profile
- Device properties, battery, memory and uptime
- One-click **Run Full Forensic Acquisition**, or extract each source on its own

**Analysis**
- Call statistics: top contacts, calls by hour, hour × weekday heatmap, duration distribution
- Calls-per-day **forecast** (ARIMA, with a linear-regression fallback)
- **KMeans** clustering of callers and **IsolationForest** anomaly detection
- Rule-based suspicious call detection (long calls, late-night calls, bursts of short calls)
- Forensic tools: critical time window around an incident, burner phone detection, activity bursts, key contacts, behavioral change detection, suspect profile, operational-security assessment
- Social network graph (calls + SMS) with centrality metrics, per-contact risk scoring, unified timeline, cross-source correlation, behavioral anomalies
- Suspicious SMS (phishing / OTP / financial / legal-threat keywords, shortened URLs, night-time messages)
- Apps of forensic interest (spyware, vault/hider apps, encrypted messengers, root tools)
- Security events in logcat, risky networks, account footprint, browser domain categories, data-exfiltration outliers (Tx vs Rx)

**Reporting**
- A combined alerts dashboard across all modules
- An AI-generated report with nine sections, rendered in the app and exported as a styled **PDF** (ReportLab)
- Executive summary and an investigator **Q&A chat** that answers only from the extracted data
- CSV export of the filtered call log and download of the raw ADB output

---

## How it works

```
 Android device ──USB / Wi-Fi ADB──►  helper.py / forensic_extractors.py
                                        (adb shell content query, dumpsys, pm, logcat)
                                                    │  raw text
                                                    ▼
                                      parse_content_query / parse_* functions
                                                    │  list[dict]
                                                    ▼
                                      preprocessor.normalize_dataframe
                                                    │  pandas DataFrame
                                                    ▼
             ┌─────────────────────────┬──────────────────────────┬─────────────────────────────┐
             ▼                         ▼                          ▼                             ▼
      preprocessor.py            forensics.py        forensic_advanced_analysis.py   forensic_visualizations.py
  (stats, ML, forecast)    (investigative heuristics)  (network, risk, correlation)        (Plotly charts)
             └─────────────────────────┴──────────────┬───────────┴─────────────────────────────┘
                                                      ▼
                                   app.py (Streamlit UI, session state)
                                                      │
                                                      ▼
                         report_generator.py / forensic_qa.py (Gemini or Ollama → PDF / answers)
```

- Every device interaction goes through `helper.run_adb_cmd`, which finds the `adb` binary itself (see [Configuration](#configuration)).
- `adb shell content query` output (`Row: 0 key=value, key=value, ...`) is turned into dictionaries by `helper.parse_content_query`.
- Phone numbers are normalized to digits (and trimmed to the last 10 digits, dropping a `91` country code) so call logs, contacts and SMS match each other.
- All extracted and derived data is kept in `st.session_state`. Nothing is written to disk unless you download an export.

---

## Project structure

| File | Lines | Responsibility |
|---|---|---|
| `app.py` | ~2300 | Streamlit entry point: login, sidebar controls, acquisition, filters, and all UI tabs |
| `helper.py` | ~250 | Finding ADB, running commands, fetching call logs/contacts/device info, parsing `content query` output, phone-number normalization |
| `forensic_extractors.py` | ~370 | Fetching SMS, MMS, contacts, browser, calendar, packages, usage, Wi‑Fi, Bluetooth, netstats, media, downloads, logcat, accounts, notifications, owner profile; parsers for SMS/packages/Wi‑Fi/calendar |
| `preprocessor.py` | ~520 | Normalizing call logs into a DataFrame, aggregations, KMeans clustering, rule-based detection, IsolationForest, ARIMA forecast, natural-language summaries, device prop/battery parsing, owner-name inference |
| `forensics.py` | ~970 | Investigative analyses: critical window, bursts, burner phones, relationships, behavior change, OPSEC, timeline, suspicious SMS/apps, logcat security, network/account/Bluetooth/browser/usage/netstats analysis |
| `forensic_advanced_analysis.py` | ~660 | NetworkX communication graph and metrics, interactive Plotly network, contact risk scores, unified timeline, cross-source correlation, communication patterns, behavioral anomalies |
| `forensic_visualizations.py` | ~720 | Plotly chart builders for every module |
| `report_generator.py` | ~880 | AI backend selection (Gemini / Ollama), finding summaries, comprehensive report, executive summary, PDF generation |
| `forensic_qa.py` | ~110 | Data-grounded Q&A over the extracted evidence |
| `requirements.txt` | | Python dependencies |
| `.devcontainer/devcontainer.json` | | Codespaces / VS Code Dev Container (Python 3.11, auto-starts Streamlit on port 8501) |

---

## Requirements

- **Python 3.10+** (the dev container uses 3.11)
- **Android SDK Platform-Tools** (`adb`): <https://developer.android.com/tools/releases/platform-tools>
- An Android device with **Developer options → USB debugging** turned on, authorized for this computer
- Optional: a **Google Gemini API key** for online AI reports
- Optional: **[Ollama](https://ollama.com)** running locally with the `llama3` model for offline AI reports

Python packages (`requirements.txt`): `streamlit`, `pandas`, `numpy`, `matplotlib`, `plotly`, `scikit-learn`, `statsmodels`, `networkx`, `reportlab`, `Pillow`, `google-genai`, `requests`.

---

## Installation

```bash
git clone https://github.com/aditya-stv/callaudit.git
cd callaudit
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

Check that ADB can see your phone:

```bash
adb devices
# List of devices attached
# XXXXXXXX    device        ← must say "device", not "unauthorized"
```

---

## Configuration

Settings are read from **environment variables first**, then from **Streamlit secrets** (`.streamlit/secrets.toml`, which is gitignored).

| Name | Required | Purpose |
|---|---|---|
| `APP_USERNAME` | **Yes** | Investigator login user ID |
| `APP_PASSWORD` | **Yes** | Investigator login password |
| `GEMINI_API_KEY` | For online AI | Google Gemini API key (model `gemini-2.5-flash`) |
| `ADB_PATH` | No | Full path to the `adb` executable, if it isn't detected automatically |

Example `.streamlit/secrets.toml`:

```toml
APP_USERNAME = "investigator"
APP_PASSWORD = "change-me"
GEMINI_API_KEY = "your-gemini-key"
```

**How `adb` is found** (`helper._resolve_adb_path`):
1. The `ADB_PATH` environment variable, if that file exists
2. `adb` on the system `PATH`
3. Common Windows locations: `C:\platform-tools\adb.exe`, `%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe`, `C:\Program Files\Android\platform-tools\adb.exe`, `D:\platform-tools\adb.exe`

**Ollama** settings are constants in `report_generator.py`: `OLLAMA_BASE_URL = "http://localhost:11434"` and `OLLAMA_MODEL = "llama3"`. To set it up:

```bash
ollama pull llama3
ollama serve
```

---

## Running the app

```bash
streamlit run app.py
```

Then open <http://localhost:8501> and log in with `APP_USERNAME` / `APP_PASSWORD`.

**Dev Container / Codespaces:** opening the repo in the dev container installs the requirements and runs `streamlit run app.py --server.enableCORS false --server.enableXsrfProtection false`, forwarding port 8501.

> ADB needs a device that the machine running Streamlit can reach. On a hosted deployment (Streamlit Cloud, Codespaces) there is no USB phone attached, so acquisition only works when the server runs on the machine the phone is plugged into, or with ADB over Wi‑Fi to a reachable device.

---

## Usage walkthrough

1. **Log in** with your investigator credentials.
2. In the sidebar under **Controls & Device Info**:
   - **Check Device** runs `adb devices` and confirms the phone is authorized.
   - **Fetch Device Info** pulls `getprop`, battery, memory and uptime, and shows model, Android version, battery level and health.
3. Under **Extraction & Analysis**:
   - **Fetch Contacts** builds a map from normalized number to name.
   - **Extract Call Logs** caches the raw call log output.
   - **Parse & Analyze** normalizes the call log, attaches contact names, and unlocks the main tabs.
4. Under **Forensic Acquisition**:
   - **Run Full Forensic Acquisition** extracts SMS, browser, calendar, apps, Wi‑Fi, accounts, MMS, media, usage stats, logs/notifications, network stats and owner profile in one pass with a progress bar. A failure in one source doesn't stop the others.
   - Or use the **Individual Extraction** buttons for one source at a time.
5. Use **Date & Type filters** in the sidebar to narrow the call log (date range and INCOMING / OUTGOING / MISSED / REJECTED / UNKNOWN).
6. Explore the tabs, generate the AI report, download the PDF, and ask follow-up questions.

---

## The UI tabs

| Tab | Contents |
|---|---|
| **Overview** | KPI matrix across all sources, module status, recent activity, app information |
| **Analytics** | Combined call + SMS activity; calls by hour; hour × weekday heatmap; calls per day with forecast; duration distribution; caller clustering |
| **Alerts** | Global risk dashboard combining alerts from Apps, SMS, Network, System logs, Identity and Usage; rule-based call detections; IsolationForest anomalies; combined risk scoring |
| **Forensics** | Critical time window, burner phones, key contacts, behavioral changes, activity bursts, suspect profile, OPSEC assessment, visual charts; advanced sub-tabs (Social Network, Contact Risk Scoring, Timeline Reconstruction, Cross-Source Correlations, Communication Patterns, Behavioral Anomalies); **AI report** generation, PDF download, executive summary, and **Q&A** |
| **Communications** | SMS analytics, suspicious-message alerts, message explorer with contact names |
| **System** | Sub-tabs for Apps (apps of interest, usage, package list), Calendar, Connectivity (browsing insights, Wi‑Fi, Bluetooth, raw network data), Media & Stats (foreground time, network traffic, Tx vs Rx outliers, media metadata), Logs (logcat and notifications), Accounts (identity footprint) |
| **Settings** | Analysis parameters (number of clusters, forecast horizon, IsolationForest contamination), clearing session data or device info, CSV / raw output export, privacy notice |

---

## Analysis methods

### Call log preprocessing (`preprocessor.normalize_dataframe`)
Maps Android `type` codes (`1` INCOMING, `2` OUTGOING, `3` MISSED, `5` REJECTED, `0` UNKNOWN), converts epoch milliseconds to datetime, and adds `duration_s`, `duration` (HH:MM:SS), `hour`, `date`, `weekday` and `name`. It tolerates schema differences between OEMs (`number` / `normalized_number` / `formatted_number`, `name` / `cached_name`, and so on).

### Machine learning
- **Caller clustering:** KMeans on standardized `[total_calls, avg_duration, pct_missed]` per number. *k* is set in Settings (default 3).
- **Anomaly detection:** IsolationForest (100 trees, contamination 0.05 by default) on `[duration_s, hour, dayofweek, count_by_number]`, rescaled to a 0–1 anomaly score. Needs at least 5 calls.
- **Forecast:** ARIMA(1,1,0) on calls per day (statsmodels), falling back to linear regression. The horizon is set in Settings (default 7 days).

### Rule-based call detection (`heuristic_suspicious`)
| Rule | Default | Score |
|---|---|---|
| Long call | ≥ 3600 s | +0.6 |
| Late-night call | 00:00–05:59 (hours 0–5), connected | +0.4 |
| Bursts of short calls | ≥ 5 calls to one number in 30 min, averaging ≤ 10 s | 0.7 |

### Investigative heuristics (`forensics.py`)
- **Burner phones:** numbers with ≥ 5 calls active for ≤ 7 days. Score = (calls / active days) / 10, capped at 1.
- **Critical window:** all activity within ±N hours (default 24, slider 1–72) of an incident date and time.
- **Activity bursts:** at least `threshold` calls inside a `window_minutes` window.
- **Suspicious SMS:** keyword groups *critical* (OTP, verify, login…, +0.4), *financial*, *threat* and *phish* (+0.2 each); links (+0.3, with extra weight for shorteners such as bit.ly or tinyurl), masked or alphanumeric senders, and night-time messages.
- **Apps of forensic interest:** package names matching spyware, vault/hide, encrypted messaging, or root/ADB tool keywords.
- Also: logcat security events, risky/open Wi‑Fi and suspicious search intent, multiple or privacy-focused accounts, Bluetooth pairings by device category, browser domain categories, foreground time from `usagestats`, per-UID Rx/Tx from `netstats`, and stealth-usage alerts.

### Advanced analysis (`forensic_advanced_analysis.py`)
- **Communication network:** a NetworkX graph from calls and SMS with degree, betweenness and closeness centrality, drawn as an interactive Plotly graph.
- **Contact risk score (0–100):** +10 per late-night call, +15 for more than 5 calls under 10 s, +20 for more than 20 calls, +10 for unsaved numbers, +15 for numbers with only calls and no SMS. Levels: HIGH > 60, MEDIUM > 30, otherwise LOW.
- A unified timeline across calls, SMS and apps; cross-source correlation (including browser and Wi‑Fi); communication patterns; behavioral anomalies.

---

## AI reporting and Q&A

**Backend selection** (`report_generator.get_available_ai_backend`):
1. If the internet is reachable (a TCP check to `8.8.8.8:53`), use **Gemini** (`gemini-2.5-flash`). This requires `GEMINI_API_KEY`.
2. Otherwise, if Ollama answers at `localhost:11434`, use **Ollama** (`llama3`).
3. Otherwise, show an error.

**Comprehensive report:** fill in the case details in the Forensics tab and click **Generate AI Forensic Report**. The prompt includes device info, call statistics, every forensic analysis, and the extra sources (SMS, apps, accounts, Wi‑Fi, browser, usage and so on). The report has nine sections:

1. Executive Summary
2. Identity Profile
3. Device & Methodology
4. Communication Analysis (Calls & SMS)
5. Social Network Mapping
6. Digital Behavior Analysis
7. Temporal & Spatial Artifacts
8. Security & Privacy Assessment
9. Conclusions & Investigative Leads (color-coded by priority)

**PDF export:** `generate_pdf_report` renders the markdown report with ReportLab, including tables, colored priority text, and charts when available.

**Investigator Q&A:** `forensic_qa.answer_forensic_question` builds a context from call stats, SMS, apps, accounts, Wi‑Fi, browser activity and the last 3 Q&A pairs. The model is told to answer **only from that data** and to say when the data isn't enough.

> When Gemini is used, summaries of the extracted data are sent to Google's API. Use Ollama (offline) for cases where data must not leave the machine.

---

## Device compatibility

- **Android 8 (Oreo) to Android 14**, which have a stable call-log schema, without root
- Single-SIM, dual-SIM and eSIM devices; USB or wireless ADB
- Tested or generally supported: Xiaomi / Redmi / POCO, Samsung (One UI), OnePlus / Nord, Realme / Oppo / Vivo, Motorola, Google Pixel, Nokia, ASUS, Lenovo
- **Root may be required** when an OEM blocks the call-log or SMS provider, SELinux blocks `content query`, or privacy features hide data. If an extraction returns 0 rows, the ROM probably restricts that provider.
- Some sources (browser provider, `dumpsys location`, `usagestats`) vary widely across Android versions and may return little or nothing.

---

## Module reference

<details>
<summary><b>helper.py</b></summary>

`run_adb_cmd(args, timeout)`, `adb_devices()`, `fetch_call_log_raw()`, `fetch_contacts_raw()`, `fetch_device_props()`, `fetch_battery()`, `fetch_meminfo()`, `fetch_uptime()`, `parse_content_query(output)`, `normalize_phone_number(number)`, `parse_contacts(output)`
</details>

<details>
<summary><b>forensic_extractors.py</b></summary>

Fetchers: `fetch_sms_raw/inbox/sent/conversations`, `fetch_mms_raw`, `fetch_contacts_full/emails/addresses`, `fetch_browser_bookmarks/searches`, `fetch_calendar_events/attendees`, `fetch_installed_packages`, `fetch_app_usage_stats`, `fetch_battery_stats`, `fetch_recent_apps`, `fetch_location_data`, `fetch_wifi_networks` (`cmd wifi list-networks`, falling back to `dumpsys wifi`), `fetch_bluetooth_devices`, `fetch_network_stats`, `fetch_media_images/videos/audio`, `fetch_downloads`, `fetch_logcat`, `fetch_accounts`, `fetch_notifications`, `fetch_owner_profile`.
Parsers: `parse_sms`, `parse_installed_packages`, `parse_wifi_networks`, `parse_calendar_events`.
</details>

<details>
<summary><b>preprocessor.py</b></summary>

`normalize_dataframe`, `most_frequent`, `calls_by_hour`, `calls_per_day`, `calls_heatmap`, `caller_features`, `cluster_callers`, `heuristic_suspicious`, `isolation_anomalies`, `forecast_calls_per_day`, `generate_nl_*` (plain-English summaries), `normalize_device_props`, `parse_battery`, `extract_potential_owner_name`
</details>

<details>
<summary><b>forensics.py</b></summary>

`analyze_critical_window`, `detect_activity_bursts`, `build_contact_network`, `get_network_metrics`, `identify_key_contacts`, `detect_burner_phones`, `analyze_contact_relationships`, `detect_behavioral_changes`, `find_repeated_patterns`, `generate_suspect_profile`, `analyze_operational_security`, `reconstruct_timeline`, `detect_suspicious_sms`, `detect_suspicious_apps`, `analyze_system_security_logs`, `detect_network_anomalies`, `analyze_account_risks`, `parse_account_details`, `parse_wifi_profiles`, `analyze_bluetooth_pairings`, `analyze_browser_domains`, `parse_app_usage_stats`, `parse_network_data_usage`, `detect_usage_anomaly_alerts`
</details>

<details>
<summary><b>forensic_advanced_analysis.py</b></summary>

`build_communication_network`, `calculate_network_metrics`, `create_interactive_network_graph`, `calculate_contact_risk_scores`, `create_timeline_view`, `cross_source_correlation`, `analyze_communication_patterns`, `detect_behavioral_anomalies`
</details>

<details>
<summary><b>forensic_visualizations.py</b></summary>

`create_timeline_chart`, `create_call_type_distribution`, `create_hourly_activity_chart`, `create_duration_histogram`, `create_top_contacts_chart`, `create_behavioral_heatmap`, `create_burner_phone_chart`, `create_sms_activity_chart`, `create_top_sms_contacts_chart`, `create_sms_hourly_chart`, `create_sms_length_dist`, `create_browser_activity_chart`, `create_browser_domain_pie`, `create_app_usage_chart`, `create_app_category_chart`, `create_app_foreground_pie`, `create_calendar_distribution_chart`, `create_log_intensity_chart`, `create_wifi_frequency_chart`, `create_bluetooth_category_chart`, `create_data_usage_bar`, `create_tx_rx_scatter`, `create_account_distribution_pie`, `save_plotly_as_image`
</details>

<details>
<summary><b>report_generator.py / forensic_qa.py</b></summary>

`check_internet_connection`, `check_ollama_available`, `get_available_ai_backend`, `generate_with_ollama`, `get_gemini_client`, `generate_finding_summary`, `generate_executive_summary`, `generate_comprehensive_report`, `format_analyses_for_prompt`, `generate_pdf_report`, `generate_timeline_narrative`, `generate_suspect_profile`; `answer_forensic_question`
</details>

---

## Known limitations

These are visible in the current code and are worth knowing before you rely on the results:

- **Phone-number normalization is India-specific.** It drops a leading `91` from 12-digit numbers and otherwise keeps the last 10 digits. Numbers from other countries with different lengths may match incorrectly.
- **Apps of interest may show no results.** The "apps of forensic interest" detection and the app KPI on the Overview tab read `st.session_state["installed_packages"]`, but extraction stores parsed apps under `apps_data`.
- **Battery-drain checks have no input.** The usage-anomaly detector accepts `batterystats_raw`, but no extraction button fills that session key (`fetch_battery_stats` exists but isn't wired into the UI).
- **The AI backend is chosen by connectivity, not by configuration.** With internet access, Gemini is always chosen, even when no `GEMINI_API_KEY` is set (that produces a configuration error instead of falling back to Ollama).
- `report_generator.py` defines `generate_executive_summary` twice; the second definition (later in the file) is the one that runs.
- `logcat` is limited to the last 1000 lines.
- Analyses use on-device timestamps as naive local datetimes; timezone is not normalized.
- There are no automated tests in the repository.

---

## Author

**Aditya Mohan Srivastava** — Android Forensic Auditor `v1.0.0-PRO`

Built for analysis and research. Use responsibly.
