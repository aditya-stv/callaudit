# Android Forensic Auditor (CallAudit)

A Streamlit web application and cross-platform command-line tool (Linux, Windows, macOS) for **forensic acquisition and analysis of Android devices over ADB**. It pulls call logs, contacts, SMS/MMS, browser history, calendar, installed apps, Wi‑Fi, accounts, usage statistics, logs and network statistics from a connected phone, then runs statistical, machine‑learning and heuristic analyses on them. It can also produce an **AI‑written investigation report** (Google Gemini online, or a local Ollama model offline), export it as a PDF, and answer investigator questions about the extracted data.

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
- [Command-line interface (Linux / Windows / macOS)](#command-line-interface-linux--windows--macos)
- [Platform setup notes](#platform-setup-notes)
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

**Command line**
- `cli.py` runs every step from a terminal on Linux, Windows or macOS, with no browser needed
- Saves each acquisition to a case folder with SHA-256 hashes, so analysis can be repeated offline on any machine

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
- In the web UI, all extracted and derived data is kept in `st.session_state`. Nothing is written to disk unless you download an export.
- The CLI writes raw ADB output to a case folder first, then parses and analyzes from those files with the same modules the web UI uses.

---

## Project structure

| File | Lines | Responsibility |
|---|---|---|
| `app.py` | ~2300 | Streamlit entry point: login, sidebar controls, acquisition, filters, and all UI tabs |
| `cli.py` | ~800 | Command-line interface: `devices`, `info`, `extract`, `analyze`, `report`, `ask`, `ui` |
| `callaudit` / `callaudit.bat` | | Launchers for the CLI on Linux/macOS and on Windows |
| `helper.py` | ~300 | Finding ADB on Windows/Linux/macOS, running commands, fetching call logs/contacts/device info, parsing `content query` output, phone-number normalization |
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
- Optional: Google Chrome or Chromium, used by `kaleido` to draw the charts in the PDF report. Without it the PDF is still created, just without charts. Run `plotly_get_chrome` to download a copy.

Python packages (`requirements.txt`): `streamlit`, `pandas`, `numpy`, `matplotlib`, `plotly`, `kaleido`, `scikit-learn`, `statsmodels`, `networkx`, `reportlab`, `Pillow`, `google-genai`, `requests`.

---

## Installation

**Linux / macOS**

```bash
git clone https://github.com/aditya-stv/callaudit.git
cd callaudit
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

**Windows (PowerShell or Command Prompt)**

```bat
git clone https://github.com/aditya-stv/callaudit.git
cd callaudit
py -3 -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

If PowerShell blocks `activate`, run `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned` once, or use Command Prompt.

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
| `APP_USERNAME` | Web UI only | Investigator login user ID |
| `APP_PASSWORD` | Web UI only | Investigator login password |
| `GEMINI_API_KEY` | For online AI | Google Gemini API key (model `gemini-2.5-flash`) |
| `AI_BACKEND` | No | `auto` (default), `gemini` or `ollama`. The CLI's `--ai` option sets it |
| `OLLAMA_BASE_URL` | No | Ollama server (default `http://localhost:11434`) |
| `OLLAMA_MODEL` | No | Ollama model (default `llama3`) |
| `ADB_PATH` | No | Full path to the `adb` executable, if it isn't detected automatically. The CLI's `--adb` option sets it |
| `ANDROID_HOME` / `ANDROID_SDK_ROOT` | No | Android SDK folder; `platform-tools/adb` inside it is checked |
| `ANDROID_SERIAL` | No | Which device to use when several are connected (standard adb variable). The CLI's `--serial` option sets it |

Set an environment variable for the current terminal session:

```bash
export GEMINI_API_KEY="your-key"        # Linux / macOS
```
```bat
set GEMINI_API_KEY=your-key             :: Windows Command Prompt
$env:GEMINI_API_KEY = "your-key"        # Windows PowerShell
```

Example `.streamlit/secrets.toml`:

```toml
APP_USERNAME = "investigator"
APP_PASSWORD = "change-me"
GEMINI_API_KEY = "your-gemini-key"
```

**How `adb` is found** (`helper._resolve_adb_path`):
1. The `ADB_PATH` environment variable, if that file exists
2. `adb` on the system `PATH`
3. `ANDROID_HOME` / `ANDROID_SDK_ROOT`, then common install locations for the current OS:
   - **Windows:** `C:\platform-tools\adb.exe`, `%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe`, `C:\Program Files\Android\platform-tools\adb.exe`, `C:\Program Files (x86)\Android\android-sdk\platform-tools\adb.exe`, `D:\platform-tools\adb.exe`
   - **Linux:** `~/Android/Sdk/platform-tools/adb`, `~/platform-tools/adb`, `/opt/platform-tools/adb`, `/usr/lib/android-sdk/platform-tools/adb`, `/usr/local/bin/adb`, `/usr/bin/adb`, `/snap/bin/adb`
   - **macOS:** `~/Library/Android/sdk/platform-tools/adb`, `/opt/homebrew/bin/adb`, `/usr/local/bin/adb`

**Ollama** uses `http://localhost:11434` and the `llama3` model unless `OLLAMA_BASE_URL` / `OLLAMA_MODEL` say otherwise. To set it up:

```bash
ollama pull llama3
ollama serve
```

---

## Running the app

```bash
streamlit run app.py
# or, on any OS:
python cli.py ui
```

Then open <http://localhost:8501> and log in with `APP_USERNAME` / `APP_PASSWORD`.

**Dev Container / Codespaces:** opening the repo in the dev container installs the requirements and runs `streamlit run app.py --server.enableCORS false --server.enableXsrfProtection false`, forwarding port 8501.

> ADB needs a device that the machine running Streamlit can reach. On a hosted deployment (Streamlit Cloud, Codespaces) there is no USB phone attached, so acquisition only works when the server runs on the machine the phone is plugged into, or with ADB over Wi‑Fi to a reachable device.

---

## Command-line interface (Linux / Windows / macOS)

`cli.py` runs the whole pipeline from a terminal, with no browser or login screen. It uses only the Python standard library on top of the project's requirements, so the same commands work in bash, zsh, PowerShell and Command Prompt.

```text
python cli.py <command> [options]          # any OS
./callaudit <command> [options]            # Linux / macOS launcher
callaudit <command> [options]              # Windows launcher (callaudit.bat)
```

On Windows, use `py -3 cli.py ...` if `python` isn't on your `PATH`.

### Commands

| Command | Needs device | What it does |
|---|---|---|
| `devices` | yes | Shows the `adb` binary in use and the connected devices |
| `info` | yes | Shows brand, model, Android version, SDK, serial, battery and uptime |
| `extract` | yes | Acquires data into a case folder (all 22 sources by default) |
| `analyze CASE_DIR` | no | Parses the case and runs every analysis; prints a summary and saves CSV/JSON |
| `report CASE_DIR` | no | Writes the AI report to `report.md` and `report.pdf` |
| `ask CASE_DIR [QUESTION]` | no | Answers a question from the case data, or starts an interactive Q&A session |
| `ui` | no | Starts the Streamlit web interface |

Global options go **before** the command: `-s/--serial SERIAL` picks a device when several are connected, and `--adb PATH` sets the adb binary. Run `python cli.py <command> --help` for every option.

### Typical session

```bash
python cli.py devices
python cli.py extract -o cases/CASE-001                 # full acquisition
python cli.py analyze cases/CASE-001                    # tables in the terminal + files on disk
python cli.py report  cases/CASE-001 --investigator "A. Investigator" --case-number CASE-001
python cli.py ask     cases/CASE-001 "Which numbers called between midnight and 5am?"
python cli.py ask     cases/CASE-001                    # interactive; type 'exit' to quit
```

Windows example (Command Prompt), with two phones connected and adb in a custom folder:

```bat
callaudit --adb C:\tools\platform-tools\adb.exe --serial R58N123ABC extract -o cases\CASE-002 --quick
callaudit analyze cases\CASE-002 --from 2026-09-01 --to 2026-09-30 --types INCOMING,OUTGOING
```

### `extract` options

| Option | Meaning |
|---|---|
| `-o DIR` | Case folder (default `cases/CASE-<timestamp>`). Running again into the same folder updates the manifest |
| `--only calls,contacts,sms` | Acquire only these sources |
| `--skip logcat,media_images` | Leave these sources out |
| `--quick` | Only `calls`, `contacts`, `device_props`, `battery`, `uptime` |
| `--list` | List all source names |

Sources: `calls`, `contacts`, `device_props`, `battery`, `meminfo`, `uptime`, `sms`, `mms`, `browser_bookmarks`, `browser_searches`, `calendar`, `apps`, `app_usage`, `batterystats`, `wifi`, `bluetooth`, `netstats`, `media_images`, `accounts`, `logcat`, `notifications`, `profile`. If one source fails (for example, the ROM blocks that provider), the others still run and the failure is recorded in the manifest.

### `analyze`, `report` and `ask` options

| Option | Meaning |
|---|---|
| `--from YYYY-MM-DD` / `--to YYYY-MM-DD` | Date filter for calls |
| `--types INCOMING,OUTGOING,MISSED,REJECTED,UNKNOWN` | Call type filter |
| `--incident "YYYY-MM-DD HH:MM"` and `--window HOURS` | Critical-window analysis around an incident (default ±24 h) |
| `--clusters N`, `--contamination X`, `--forecast-days N`, `--top N` | Same parameters as the web UI's Settings tab |
| `analyze --json` | Print all results as JSON (for scripts) instead of tables |
| `analyze -o DIR` / `report -o DIR` | Write outputs somewhere other than the case folder |
| `report --ai {auto,gemini,ollama}` / `ask --ai ...` | Choose the AI backend; `--ollama-model NAME` picks the Ollama model |
| `report --owner`, `--investigator`, `--case-number`, `--classification`, `--no-pdf` | Report metadata and output |
| `ask --fast` | Skip re-running the analyses before answering |

### Case folder layout

```text
cases/CASE-001/
├── manifest.json        # host OS, adb path/devices, and per-source status, size, SHA-256, timestamp
├── raw/                 # exact adb output per source (calls.txt, sms.txt, ...)
├── parsed/              # calls.csv, contacts.csv, sms.csv, apps.csv, calendar.csv
├── analysis/            # one CSV/JSON per analysis (burner_phones.csv, contact_risk_scores.csv, ...)
├── report.md
└── report.pdf
```

Because `analyze`, `report` and `ask` only read the case folder, you can acquire on one machine (for example, a Windows laptop next to the phone) and analyze on another (for example, a Linux workstation). The `cases/` folder is gitignored so evidence is never committed by accident.

Exit codes: `0` success, `1` failure (no device, no data, AI or PDF error), `2` invalid arguments, `130` interrupted.

---

## Platform setup notes

**Linux**
- Install adb with `sudo apt install adb` (Debian/Ubuntu), `sudo dnf install android-tools` (Fedora) or `sudo pacman -S android-tools` (Arch), or unpack Platform-Tools to `~/platform-tools`.
- If `adb devices` shows `no permissions`, install your distribution's `android-udev-rules` package (or add a udev rule for the phone's USB vendor ID), add yourself to the `plugdev` group, reconnect the phone and run `adb kill-server`.
- The CLI works on headless servers and over SSH. Charts use a non-GUI backend, and `python cli.py ui --headless` serves the web UI without opening a browser.

**Windows**
- Unzip Platform-Tools to `C:\platform-tools`, which is detected automatically, or add its folder to `PATH`.
- Some phones (Samsung, Xiaomi and others) need the OEM USB driver or the Google USB Driver before `adb devices` lists them.
- `adb` runs without opening console windows, and output is printed as UTF-8, so contact names in any language display correctly in Windows Terminal. Older `cmd.exe` fonts may still show some characters as `?`.

**macOS**
- `brew install android-platform-tools`, or unpack Platform-Tools to `~/Library/Android/sdk/platform-tools`.

**Wireless ADB (all platforms)**: `adb pair IP:PORT` (Android 11+) or `adb tcpip 5555` followed by `adb connect IP:5555`, then use the CLI as usual. Add `--serial IP:5555` if a USB device is also connected.

---

## Usage walkthrough

This section describes the web UI. For the terminal, see [Command-line interface](#command-line-interface-linux--windows--macos).

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
1. If `AI_BACKEND` (or the CLI's `--ai`) is `gemini` or `ollama`, use that backend.
2. Otherwise, if the internet is reachable (a TCP check to `8.8.8.8:53`) **and** `GEMINI_API_KEY` is set, use **Gemini** (`gemini-2.5-flash`).
3. Otherwise, if Ollama answers at `OLLAMA_BASE_URL`, use **Ollama** (`OLLAMA_MODEL`, default `llama3`).
4. Otherwise, show an error.

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
- **Apps of interest may show no results in the web UI.** The "apps of forensic interest" detection and the app KPI on the Overview tab read `st.session_state["installed_packages"]`, but extraction stores parsed apps under `apps_data`. The CLI passes the parsed apps directly, so it isn't affected.
- **Battery-drain checks have no input in the web UI.** The usage-anomaly detector accepts `batterystats_raw`, but no web UI button fills that session key. The CLI acquires it as the `batterystats` source.
- `report_generator.py` defines `generate_executive_summary` twice; the second definition (later in the file) is the one that runs.
- `logcat` is limited to the last 1000 lines.
- Analyses use on-device timestamps as naive local datetimes; timezone is not normalized.
- There are no automated tests in the repository.

---

## Author

**Aditya Mohan Srivastava** — Android Forensic Auditor `v1.0.0-PRO`

Built for analysis and research. Use responsibly.
