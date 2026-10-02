#!/usr/bin/env python3
# cli.py - Command-line interface for Android Forensic Auditor (Linux, Windows, macOS)
"""
Run acquisition, analysis, AI reporting and Q&A from a terminal, without the Streamlit UI.

Workflow:
    python cli.py devices                         # check that adb sees the phone
    python cli.py extract -o cases/CASE-001       # pull data from the phone into a case folder
    python cli.py analyze cases/CASE-001          # analyze offline (no phone needed)
    python cli.py report  cases/CASE-001          # AI report -> report.md + report.pdf
    python cli.py ask     cases/CASE-001 "Who did the owner call most at night?"

Run `python cli.py <command> --help` for the options of each command.
"""
import argparse
import hashlib
import json
import os
import platform
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

# Charts are rendered to files only, never to a window (also needed on headless Linux)
os.environ.setdefault("MPLBACKEND", "Agg")

APP_VERSION = "v1.0.0-PRO"
BASE_DIR = Path(__file__).resolve().parent

# Ordered acquisition sources: name -> (module, function, description)
SOURCES = {
    "calls": ("helper", "fetch_call_log_raw", "Call log"),
    "contacts": ("helper", "fetch_contacts_raw", "Contacts"),
    "device_props": ("helper", "fetch_device_props", "Device properties (getprop)"),
    "battery": ("helper", "fetch_battery", "Battery status"),
    "meminfo": ("helper", "fetch_meminfo", "Memory info"),
    "uptime": ("helper", "fetch_uptime", "Uptime"),
    "sms": ("forensic_extractors", "fetch_sms_raw", "SMS messages"),
    "mms": ("forensic_extractors", "fetch_mms_raw", "MMS messages"),
    "browser_bookmarks": ("forensic_extractors", "fetch_browser_bookmarks", "Browser bookmarks"),
    "browser_searches": ("forensic_extractors", "fetch_browser_searches", "Browser searches"),
    "calendar": ("forensic_extractors", "fetch_calendar_events", "Calendar events"),
    "apps": ("forensic_extractors", "fetch_installed_packages", "Installed apps"),
    "app_usage": ("forensic_extractors", "fetch_app_usage_stats", "App usage stats"),
    "batterystats": ("forensic_extractors", "fetch_battery_stats", "Battery stats"),
    "wifi": ("forensic_extractors", "fetch_wifi_networks", "Wi-Fi networks"),
    "bluetooth": ("forensic_extractors", "fetch_bluetooth_devices", "Bluetooth pairings"),
    "netstats": ("forensic_extractors", "fetch_network_stats", "Network data usage"),
    "media_images": ("forensic_extractors", "fetch_media_images", "Image metadata"),
    "accounts": ("forensic_extractors", "fetch_accounts", "Accounts"),
    "logcat": ("forensic_extractors", "fetch_logcat", "System log (logcat)"),
    "notifications": ("forensic_extractors", "fetch_notifications", "Notifications"),
    "profile": ("forensic_extractors", "fetch_owner_profile", "Owner profile"),
}
QUICK_SOURCES = ["calls", "contacts", "device_props", "battery", "uptime"]


# ---------- Console helpers ----------
def _setup_console():
    """Make Unicode output safe on Windows consoles (cp1252 etc.)."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass


def info(msg):
    print(msg, flush=True)


def warn(msg):
    print(f"[!] {msg}", file=sys.stderr, flush=True)


def die(msg, code=1):
    print(f"[x] {msg}", file=sys.stderr, flush=True)
    sys.exit(code)


def heading(title):
    info("")
    info(title)
    info("-" * len(title))


def _table(df, max_rows=10):
    """Render the first rows of a DataFrame as plain text."""
    import pandas as pd

    if df is None or df.empty:
        return "  (none)"
    with pd.option_context("display.width", 160, "display.max_columns", 12, "display.max_colwidth", 60):
        return df.head(max_rows).to_string(index=False)


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _to_jsonable(obj):
    """Convert analysis results (DataFrames, numpy, timestamps, graphs) to JSON-friendly data."""
    import numpy as np
    import pandas as pd

    if isinstance(obj, pd.DataFrame):
        return json.loads(obj.to_json(orient="records", date_format="iso", default_handler=str))
    if isinstance(obj, pd.Series):
        return _to_jsonable(obj.to_dict())
    if isinstance(obj, dict):
        return {str(k): _to_jsonable(v) for k, v in obj.items()}
    if isinstance(obj, (list, tuple, set)):
        return [_to_jsonable(v) for v in obj]
    if isinstance(obj, (np.integer,)):
        return int(obj)
    if isinstance(obj, (np.floating,)):
        return None if np.isnan(obj) else float(obj)
    if isinstance(obj, (np.bool_,)):
        return bool(obj)
    if isinstance(obj, (pd.Timestamp, datetime)):
        return obj.isoformat()
    if obj is pd.NaT or obj is None:
        return None
    try:
        if pd.isna(obj):
            return None
    except (TypeError, ValueError):
        pass
    if isinstance(obj, (str, int, float, bool)):
        return obj
    return str(obj)


def _count(result):
    import pandas as pd

    if isinstance(result, pd.DataFrame):
        return len(result)
    if isinstance(result, (list, dict, tuple)):
        return len(result)
    return 1 if result else 0


# ---------- Case folder ----------
def _raw_dir(case_dir):
    return Path(case_dir) / "raw"


def load_case(case_dir):
    """Read raw acquisition files from a case folder into {source: text}."""
    case_dir = Path(case_dir)
    raw_dir = _raw_dir(case_dir)
    if not raw_dir.is_dir():
        die(f"'{case_dir}' is not a case folder (missing '{raw_dir.name}/'). Run 'extract' first.")
    raw = {}
    for name in SOURCES:
        path = raw_dir / f"{name}.txt"
        text = path.read_text(encoding="utf-8", errors="ignore") if path.exists() else ""
        raw[name] = text if text.strip() else ""
    return raw


def _manifest(case_dir):
    path = Path(case_dir) / "manifest.json"
    if path.exists():
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            pass
    return {}


# ---------- Data preparation (mirrors app.py) ----------
def build_dataset(raw, date_from=None, date_to=None, call_types=None):
    """Parse raw acquisition text into the DataFrames and lists the analyses expect."""
    import pandas as pd
    from helper import parse_content_query, parse_contacts
    from preprocessor import normalize_dataframe
    from forensic_extractors import parse_sms, parse_installed_packages, parse_calendar_events

    df = normalize_dataframe(parse_content_query(raw.get("calls", "")))
    contacts_map = parse_contacts(raw.get("contacts", ""))

    # Call-log name first, then the contact book
    if contacts_map:
        df["saved_name"] = df["name"].fillna(df["number"].map(contacts_map)).fillna("")
    else:
        df["saved_name"] = df["name"].fillna("")
    df = df.drop(columns=["name"], errors="ignore")

    if date_from:
        df = df[df["date"] >= date_from]
    if date_to:
        df = df[df["date"] <= date_to]
    if call_types:
        df = df[df["call_type"].isin(call_types)]
    df = df.reset_index(drop=True)

    sms_data = parse_sms(raw["sms"]) if raw.get("sms") else []
    sms_df = pd.DataFrame(sms_data)
    if not sms_df.empty:
        sms_df["datetime"] = pd.to_datetime(pd.to_numeric(sms_df["date"], errors="coerce"), unit="ms", errors="coerce")

    apps_data = parse_installed_packages(raw["apps"]) if raw.get("apps") else []
    calendar_events = parse_calendar_events(raw["calendar"]) if raw.get("calendar") else []

    return {
        "calls": df,
        "contacts_map": contacts_map,
        "sms_data": sms_data,
        "sms_df": sms_df,
        "apps_data": apps_data,
        "apps_df": pd.DataFrame(apps_data),
        "calendar_events": calendar_events,
    }


def device_info_from_raw(raw):
    from preprocessor import normalize_device_props, parse_battery

    if not raw.get("device_props"):
        return None
    props = normalize_device_props(raw["device_props"])
    battery = parse_battery(raw.get("battery", "")) if raw.get("battery") else {}
    level = battery.get("level")
    uptime = raw.get("uptime", "").strip().splitlines()
    return {
        "model": props.get("ro.product.model", props.get("ro.product.device", "Unknown")),
        "brand": props.get("ro.product.brand", props.get("ro.product.manufacturer", "Unknown")),
        "android_version": props.get("ro.build.version.release", "Unknown"),
        "sdk": props.get("ro.build.version.sdk", "Unknown"),
        "serial": props.get("ro.serialno", "Unknown"),
        "battery_level": f"{level}%" if level else "Unknown",
        "uptime": uptime[0] if uptime else "Unknown",
    }


def run_analyses(data, raw, args):
    """Run every analysis that has input data. Returns {name: result}; failures are reported and skipped."""
    import pandas as pd
    import preprocessor as pp
    import forensics as fx
    import forensic_advanced_analysis as adv

    df = data["calls"]
    sms_df = data["sms_df"]
    apps_df = data["apps_df"]
    sms_arg = sms_df if not sms_df.empty else None
    apps_arg = apps_df if not apps_df.empty else None
    results = {}

    def step(name, fn):
        try:
            results[name] = fn()
        except Exception as e:
            warn(f"{name}: skipped ({e})")

    if not df.empty:
        step("top_contacts", lambda: pp.most_frequent(df, top_n=args.top))
        step("calls_by_hour", lambda: pp.calls_by_hour(df).reset_index())
        step("calls_per_day", lambda: pp.calls_per_day(df))
        step("forecast", lambda: pp.forecast_calls_per_day(pp.calls_per_day(df), days_ahead=args.forecast_days))
        step("caller_clusters", lambda: pp.cluster_callers(pp.caller_features(df), k=args.clusters))
        step("heuristic_suspicious", lambda: pp.heuristic_suspicious(df))
        step("ai_anomalies", lambda: pp.isolation_anomalies(df, contamination=args.contamination))
        step("burner_phones", lambda: fx.detect_burner_phones(df))
        step("key_contacts", lambda: fx.identify_key_contacts(df))
        step("behavioral_changes", lambda: fx.detect_behavioral_changes(df))
        step("activity_bursts", lambda: fx.detect_activity_bursts(df))
        step("relationships", lambda: fx.analyze_contact_relationships(df))
        step("repeated_patterns", lambda: fx.find_repeated_patterns(df))
        step("suspect_profile", lambda: fx.generate_suspect_profile(df))
        step("opsec", lambda: fx.analyze_operational_security(df))
        step("contact_risk_scores", lambda: adv.calculate_contact_risk_scores(df, sms_arg, apps_arg))
        step("network_metrics", lambda: adv.calculate_network_metrics(adv.build_communication_network(df, sms_arg)))
        step("communication_patterns", lambda: adv.analyze_communication_patterns(df, sms_arg)[0])
        step("behavioral_anomalies", lambda: adv.detect_behavioral_anomalies(df, sms_arg)[0])
        step("cross_source_correlation", lambda: adv.cross_source_correlation(
            df, sms_arg, apps_arg, raw.get("browser_searches") or None, raw.get("wifi") or None))
        if args.incident:
            step("critical_window", lambda: fx.analyze_critical_window(df, args.incident, args.window, args.window))

    if not sms_df.empty:
        step("suspicious_sms", lambda: fx.detect_suspicious_sms(sms_df))
    if not apps_df.empty:
        step("suspicious_apps", lambda: fx.detect_suspicious_apps(apps_df))
    if raw.get("logcat"):
        step("security_logs", lambda: fx.analyze_system_security_logs(raw["logcat"]))
    if raw.get("wifi") or raw.get("browser_searches"):
        step("network_anomalies", lambda: fx.detect_network_anomalies(raw.get("wifi", ""), raw.get("browser_searches", "")))
    if raw.get("wifi"):
        step("wifi_profiles", lambda: fx.parse_wifi_profiles(raw["wifi"]))
    if raw.get("bluetooth"):
        step("bluetooth_pairings", lambda: fx.analyze_bluetooth_pairings(raw["bluetooth"]))
    if raw.get("browser_searches"):
        step("browser_categories", lambda: fx.analyze_browser_domains(raw["browser_searches"]))
    if raw.get("accounts"):
        step("account_findings", lambda: fx.analyze_account_risks(raw["accounts"]))
        step("parsed_accounts", lambda: fx.parse_account_details(raw["accounts"]))
    if raw.get("app_usage"):
        step("parsed_app_usage", lambda: fx.parse_app_usage_stats(raw["app_usage"]))
    if raw.get("netstats"):
        step("parsed_net_traffic", lambda: fx.parse_network_data_usage(raw["netstats"]))
    if raw.get("app_usage") or raw.get("netstats") or raw.get("batterystats"):
        net_df = results.get("parsed_net_traffic", pd.DataFrame())
        step("raw_anomaly_alerts", lambda: fx.detect_usage_anomaly_alerts(
            raw.get("app_usage", ""), net_df, raw.get("batterystats", "")))
    return results


def _prepare(args):
    raw = load_case(args.case_dir)
    data = build_dataset(raw, args.date_from, args.date_to, args.types)
    if data["calls"].empty and not data["sms_data"]:
        warn("No call log or SMS records found in this case (after filters).")
    return raw, data


# ---------- Commands ----------
def cmd_devices(args):
    import helper

    info(f"adb: {helper.ADB_PATH}")
    try:
        info(helper.run_adb_cmd(["version"]).strip().splitlines()[0])
        out = helper.run_adb_cmd(["devices", "-l"])
    except RuntimeError as e:
        die(str(e))
    info(out.strip())
    lines = [l for l in out.splitlines()[1:] if l.strip()]
    if not any(l.split()[1] == "device" for l in lines if len(l.split()) > 1):
        warn("No authorized device. Enable USB debugging and accept the prompt on the phone.")
        return 1
    return 0


def _require_device():
    import helper

    try:
        state = helper.run_adb_cmd(["get-state"], timeout=15).strip()
    except RuntimeError as e:
        die(f"No usable device: {str(e).strip()}")
    if state != "device":
        die(f"Device state is '{state}'. Unlock the phone and accept the USB debugging prompt.")


def cmd_info(args):
    from helper import fetch_device_props, fetch_battery, fetch_uptime

    _require_device()
    raw = {"device_props": fetch_device_props(), "battery": fetch_battery(), "uptime": fetch_uptime()}
    dev = device_info_from_raw(raw) or {}
    heading("Device information")
    for key in ("brand", "model", "android_version", "sdk", "serial", "battery_level", "uptime"):
        info(f"  {key.replace('_', ' ').title():<16} {dev.get(key, 'Unknown')}")
    return 0


def _select_sources(args):
    if args.list:
        for name, (_, _, desc) in SOURCES.items():
            info(f"  {name:<18} {desc}")
        sys.exit(0)
    names = list(SOURCES)
    if args.quick:
        names = list(QUICK_SOURCES)
    if args.only:
        names = [n.strip() for n in args.only.split(",") if n.strip()]
    unknown = [n for n in names + (args.skip.split(",") if args.skip else []) if n.strip() and n.strip() not in SOURCES]
    if unknown:
        die(f"Unknown source(s): {', '.join(unknown)}. Use --list to see valid names.", 2)
    if args.skip:
        skip = {n.strip() for n in args.skip.split(",")}
        names = [n for n in names if n not in skip]
    return names


def cmd_extract(args):
    import importlib
    import helper

    names = _select_sources(args)
    case_dir = Path(args.output or Path("cases") / f"CASE-{datetime.now():%Y%m%d-%H%M%S}")
    raw_dir = _raw_dir(case_dir)
    raw_dir.mkdir(parents=True, exist_ok=True)

    _require_device()
    try:
        devices_out = helper.run_adb_cmd(["devices", "-l"]).strip()
    except RuntimeError:
        devices_out = ""

    manifest = _manifest(case_dir)
    manifest.update({
        "tool": "Android Forensic Auditor CLI",
        "version": APP_VERSION,
        "host": {"os": platform.platform(), "python": platform.python_version(), "user": os.environ.get("USERNAME") or os.environ.get("USER", "")},
        "adb_path": helper.ADB_PATH,
        "adb_devices": devices_out,
        "serial": os.environ.get("ANDROID_SERIAL", ""),
    })
    sources = manifest.setdefault("sources", {})

    info(f"Acquiring {len(names)} source(s) into {case_dir}")
    ok = 0
    for i, name in enumerate(names, 1):
        module, func, desc = SOURCES[name]
        prefix = f"[{i:>2}/{len(names)}] {desc:<28}"
        started = time.time()
        try:
            text = getattr(importlib.import_module(module), func)()
            path = raw_dir / f"{name}.txt"
            path.write_bytes(text.encode("utf-8"))
            sources[name] = {
                "status": "ok",
                "file": f"raw/{name}.txt",
                "bytes": path.stat().st_size,
                "sha256": _sha256(path),
                "acquired_at": datetime.now().isoformat(timespec="seconds"),
                "seconds": round(time.time() - started, 2),
            }
            ok += 1
            info(f"{prefix} ok   ({sources[name]['bytes']:,} bytes)")
        except Exception as e:
            sources[name] = {"status": "failed", "error": str(e).strip()[:500],
                             "acquired_at": datetime.now().isoformat(timespec="seconds")}
            lines = [l.strip() for l in str(e).splitlines() if l.strip()]
            info(f"{prefix} FAILED ({lines[-1][:80] if lines else 'error'})")

    manifest["updated_at"] = datetime.now().isoformat(timespec="seconds")
    (case_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    info(f"\n{ok}/{len(names)} sources acquired. Manifest with SHA-256 hashes: {case_dir / 'manifest.json'}")
    if ok == 0:
        return 1
    info(f"Next: python cli.py analyze \"{case_dir}\"")
    return 0


def _print_analysis_summary(data, results, raw):
    import pandas as pd

    df = data["calls"]
    heading("Case overview")
    info(f"  Call records       {len(df)}")
    if not df.empty:
        info(f"  Date range         {df['datetime'].min()}  ->  {df['datetime'].max()}")
        info(f"  Unique numbers     {df['number'].nunique()}")
        info(f"  Call types         {df['call_type'].value_counts().to_dict()}")
    info(f"  Contacts           {len(data['contacts_map'])}")
    info(f"  SMS messages       {len(data['sms_data'])}")
    info(f"  Installed apps     {len(data['apps_data'])}")
    info(f"  Calendar events    {len(data['calendar_events'])}")

    dev = device_info_from_raw(raw)
    if dev:
        info(f"  Device             {dev['brand']} {dev['model']} (Android {dev['android_version']}, SDK {dev['sdk']})")

    if "top_contacts" in results:
        top = results["top_contacts"].copy()
        if not top.empty and "saved_name" in df.columns:
            names = df.groupby("number")["saved_name"].first()
            top.insert(1, "name", top["number"].map(names).fillna(""))
        heading("Top contacts")
        info(_table(top))

    sections = [
        ("contact_risk_scores", "Highest-risk contacts", ["contact", "risk_score", "risk_level", "call_count", "reasons"]),
        ("burner_phones", "Possible burner phones", ["number", "total_calls", "active_days", "suspicion_score"]),
        ("heuristic_suspicious", "Rule-based suspicious calls", ["number", "datetime", "call_type", "duration_s", "reason"]),
        ("ai_anomalies", "IsolationForest anomalies", ["number", "datetime", "call_type", "duration_s", "anomaly_score"]),
        ("suspicious_sms", "Suspicious SMS", ["datetime", "address", "score", "reasons"]),
        ("suspicious_apps", "Apps of forensic interest", None),
    ]
    for key, title, cols in sections:
        res = results.get(key)
        if isinstance(res, pd.DataFrame):
            heading(f"{title} ({len(res)})")
            if cols:
                res = res[[c for c in cols if c in res.columns]]
            info(_table(res, max_rows=8))

    if "critical_window" in results:
        cw = results["critical_window"]
        heading("Critical window")
        for side in ("before", "after"):
            if isinstance(cw, dict) and side in cw:
                info(f"  {side:<7} calls={cw[side].get('count')} unique_numbers={cw[side].get('unique_numbers')}")

    heading("Other findings")
    for key, res in results.items():
        if key in {"top_contacts", "critical_window"} or key in {s[0] for s in sections}:
            continue
        info(f"  {key:<26} {_count(res)} item(s)")


def _save_results(out_dir, data, results):
    import pandas as pd

    out_dir = Path(out_dir)
    (out_dir / "parsed").mkdir(parents=True, exist_ok=True)
    (out_dir / "analysis").mkdir(parents=True, exist_ok=True)

    data["calls"].to_csv(out_dir / "parsed" / "calls.csv", index=False)
    pd.DataFrame(sorted(data["contacts_map"].items()), columns=["number", "name"]).to_csv(
        out_dir / "parsed" / "contacts.csv", index=False)
    for key, name in (("sms_df", "sms.csv"), ("apps_df", "apps.csv")):
        if not data[key].empty:
            data[key].to_csv(out_dir / "parsed" / name, index=False)
    if data["calendar_events"]:
        pd.DataFrame(data["calendar_events"]).to_csv(out_dir / "parsed" / "calendar.csv", index=False)

    for name, res in results.items():
        if isinstance(res, pd.DataFrame):
            res.to_csv(out_dir / "analysis" / f"{name}.csv", index=False)
        else:
            (out_dir / "analysis" / f"{name}.json").write_text(
                json.dumps(_to_jsonable(res), indent=2), encoding="utf-8")


def cmd_analyze(args):
    raw, data = _prepare(args)
    results = run_analyses(data, raw, args)
    out_dir = Path(args.output or args.case_dir)
    _save_results(out_dir, data, results)

    if args.json:
        summary = {
            "case_dir": str(args.case_dir),
            "calls": len(data["calls"]),
            "contacts": len(data["contacts_map"]),
            "sms": len(data["sms_data"]),
            "apps": len(data["apps_data"]),
            "device": device_info_from_raw(raw),
            "results": {k: _to_jsonable(v) for k, v in results.items()},
        }
        print(json.dumps(summary, indent=2))
    else:
        _print_analysis_summary(data, results, raw)
        info(f"\nSaved parsed data to {out_dir / 'parsed'} and results to {out_dir / 'analysis'}")
    return 0


def _forensic_bundle(data, results, raw):
    """Build the forensic_analyses / full_forensic_data dicts the report generator expects."""
    analyses = {k: results[k] for k in ("burner_phones", "key_contacts", "behavioral_changes", "activity_bursts",
                                        "relationships", "suspect_profile", "opsec") if k in results}
    full = {
        "sms_data": data["sms_data"] or None,
        "browser_searches": raw.get("browser_searches") or None,
        "apps_data": data["apps_data"] or None,
        "calendar_events": data["calendar_events"] or None,
        "wifi_raw": raw.get("wifi") or None,
        "logcat_raw": raw.get("logcat") or None,
        "app_usage_raw": raw.get("app_usage") or None,
        "netstats_raw": raw.get("netstats") or None,
    }
    for key in ("suspicious_sms", "suspicious_apps", "security_logs", "network_anomalies", "wifi_profiles",
                "bluetooth_pairings", "browser_categories", "parsed_app_usage", "parsed_net_traffic",
                "raw_anomaly_alerts", "account_findings", "parsed_accounts"):
        full[key] = results.get(key)
    return analyses, full


def _apply_ai_backend(args):
    if getattr(args, "ai", None) and args.ai != "auto":
        os.environ["AI_BACKEND"] = args.ai
    if getattr(args, "ollama_model", None):
        os.environ["OLLAMA_MODEL"] = args.ollama_model


def cmd_report(args):
    _apply_ai_backend(args)
    raw, data = _prepare(args)
    if data["calls"].empty:
        die("The report needs call log records. Extract 'calls' first.")
    results = run_analyses(data, raw, args)

    from preprocessor import extract_potential_owner_name
    from report_generator import generate_comprehensive_report, generate_pdf_report, get_available_ai_backend

    backend = get_available_ai_backend()
    if backend is None:
        die("No AI backend available. Set GEMINI_API_KEY (online) or start Ollama (offline), or pass --ai.")
    info(f"Generating report with {backend}... this can take a minute or two.")

    owner = args.owner or extract_potential_owner_name(raw.get("accounts") or None, raw.get("profile") or None)
    case_info = {
        "case_number": args.case_number or _manifest(args.case_dir).get("case_number") or Path(args.case_dir).name,
        "investigator": args.investigator or "",
        "device_owner": owner,
        "classification": args.classification,
        "analysis_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "app_version": APP_VERSION,
    }
    analyses, full = _forensic_bundle(data, results, raw)
    report_text = generate_comprehensive_report(case_info, data["calls"], analyses, device_info_from_raw(raw), full)
    if not report_text or report_text.lstrip().startswith(("**ERROR**", "Error")):
        die(f"Report generation failed:\n{report_text}")

    out_dir = Path(args.output or args.case_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    md_path = out_dir / "report.md"
    md_path.write_text(report_text, encoding="utf-8")
    info(f"Report saved: {md_path}")

    if not args.no_pdf:
        pdf_path = out_dir / "report.pdf"
        try:
            generate_pdf_report(report_text, case_info, str(pdf_path), df=data["calls"], full_forensic_data=full)
            info(f"PDF saved:    {pdf_path}")
        except Exception as e:
            warn(f"PDF generation failed: {e}")
            return 1
    return 0


def cmd_ask(args):
    _apply_ai_backend(args)
    raw, data = _prepare(args)
    if data["calls"].empty:
        die("Q&A needs call log records. Extract 'calls' first.")
    results = run_analyses(data, raw, args) if not args.fast else {}

    from forensic_qa import answer_forensic_question

    _, full = _forensic_bundle(data, results, raw)
    history = []

    def ask(question):
        answer = answer_forensic_question(question, data["calls"], full, history)
        history.append({"question": question, "answer": answer})
        info(answer.strip())

    if args.question:
        ask(" ".join(args.question))
        return 0

    info("Interactive Q&A. Answers use only the data in this case. Type 'exit' or press Ctrl+C to quit.")
    while True:
        try:
            question = input("\nQ> ").strip()
        except (EOFError, KeyboardInterrupt):
            info("")
            return 0
        if question.lower() in {"exit", "quit", "q"}:
            return 0
        if question:
            ask(question)


def cmd_ui(args):
    """Launch the Streamlit app with the current Python interpreter."""
    cmd = [sys.executable, "-m", "streamlit", "run", str(BASE_DIR / "app.py"), "--server.port", str(args.port)]
    if args.headless:
        cmd += ["--server.headless", "true"]
    try:
        return subprocess.call(cmd)
    except KeyboardInterrupt:
        return 0


# ---------- Argument parsing ----------
def _date(value):
    try:
        return datetime.strptime(value, "%Y-%m-%d").date()
    except ValueError:
        raise argparse.ArgumentTypeError(f"invalid date '{value}', expected YYYY-MM-DD")


def _datetime(value):
    for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    raise argparse.ArgumentTypeError(f"invalid date/time '{value}', expected 'YYYY-MM-DD HH:MM'")


def _types(value):
    return [t.strip().upper() for t in value.split(",") if t.strip()]


def build_parser():
    parser = argparse.ArgumentParser(
        prog="cli.py",
        description="Android Forensic Auditor - command-line interface (Linux, Windows, macOS).",
        epilog="Example: python cli.py extract -o cases/CASE-001 && python cli.py analyze cases/CASE-001",
    )
    parser.add_argument("--version", action="version", version=f"Android Forensic Auditor {APP_VERSION}")
    parser.add_argument("-s", "--serial", help="device serial to use when several are connected (sets ANDROID_SERIAL)")
    parser.add_argument("--adb", metavar="PATH", help="path to the adb executable (overrides auto-detection)")
    sub = parser.add_subparsers(dest="command", metavar="<command>")
    sub.required = True

    p = sub.add_parser("devices", help="show the adb binary in use and connected devices")
    p.set_defaults(func=cmd_devices)

    p = sub.add_parser("info", help="show model, Android version, battery and uptime of the device")
    p.set_defaults(func=cmd_info)

    p = sub.add_parser("extract", help="acquire data from the device into a case folder")
    p.add_argument("-o", "--output", metavar="DIR", help="case folder (default: cases/CASE-<timestamp>)")
    p.add_argument("--only", metavar="LIST", help="comma-separated sources to acquire, e.g. calls,contacts,sms")
    p.add_argument("--skip", metavar="LIST", help="comma-separated sources to leave out")
    p.add_argument("--quick", action="store_true", help=f"only {', '.join(QUICK_SOURCES)}")
    p.add_argument("--list", action="store_true", help="list available sources and exit")
    p.set_defaults(func=cmd_extract)

    def add_case_options(p):
        p.add_argument("case_dir", help="case folder created by 'extract'")
        p.add_argument("--from", dest="date_from", type=_date, metavar="YYYY-MM-DD", help="only calls on/after this date")
        p.add_argument("--to", dest="date_to", type=_date, metavar="YYYY-MM-DD", help="only calls on/before this date")
        p.add_argument("--types", type=_types, metavar="LIST",
                       help="call types to keep: INCOMING,OUTGOING,MISSED,REJECTED,UNKNOWN")
        p.add_argument("--clusters", type=int, default=3, help="KMeans clusters for caller clustering (default 3)")
        p.add_argument("--contamination", type=float, default=0.05, help="IsolationForest contamination (default 0.05)")
        p.add_argument("--forecast-days", type=int, default=7, help="days to forecast (default 7)")
        p.add_argument("--top", type=int, default=10, help="number of top contacts (default 10)")
        p.add_argument("--incident", type=_datetime, metavar="'YYYY-MM-DD HH:MM'",
                       help="analyze activity around this incident time")
        p.add_argument("--window", type=int, default=24, help="hours before/after the incident (default 24)")

    def add_ai_options(p):
        p.add_argument("--ai", choices=["auto", "gemini", "ollama"], default="auto",
                       help="AI backend (default auto: Gemini if online with a key, else Ollama)")
        p.add_argument("--ollama-model", metavar="NAME", help="Ollama model (default llama3 or $OLLAMA_MODEL)")

    p = sub.add_parser("analyze", help="run all analyses on a case folder (no device needed)")
    add_case_options(p)
    p.add_argument("-o", "--output", metavar="DIR", help="where to write parsed/ and analysis/ (default: case folder)")
    p.add_argument("--json", action="store_true", help="print results as JSON instead of tables")
    p.set_defaults(func=cmd_analyze)

    p = sub.add_parser("report", help="generate the AI forensic report (Markdown + PDF)")
    add_case_options(p)
    add_ai_options(p)
    p.add_argument("-o", "--output", metavar="DIR", help="where to write report.md/report.pdf (default: case folder)")
    p.add_argument("--case-number", help="case number (default: case folder name)")
    p.add_argument("--investigator", help="investigator name")
    p.add_argument("--owner", help="device owner / suspect (default: inferred from accounts/profile)")
    p.add_argument("--classification", default="CONFIDENTIAL",
                   choices=["CONFIDENTIAL", "SECRET", "TOP SECRET", "UNCLASSIFIED"])
    p.add_argument("--no-pdf", action="store_true", help="only write report.md")
    p.set_defaults(func=cmd_report)

    p = sub.add_parser("ask", help="ask questions about a case (one question, or interactive)")
    add_case_options(p)
    add_ai_options(p)
    p.add_argument("question", nargs="*", help="question to ask; omit for an interactive session")
    p.add_argument("--fast", action="store_true", help="skip running analyses first (uses parsed data only)")
    p.set_defaults(func=cmd_ask)

    p = sub.add_parser("ui", help="launch the Streamlit web interface")
    p.add_argument("--port", type=int, default=8501, help="port (default 8501)")
    p.add_argument("--headless", action="store_true", help="don't open a browser (servers / SSH sessions)")
    p.set_defaults(func=cmd_ui)
    return parser


def main(argv=None):
    _setup_console()
    parser = build_parser()
    args, extra = parser.parse_known_args(argv)
    # argparse can't place a free-text question after options; collect it here
    if extra and args.command == "ask" and not any(e.startswith("-") for e in extra):
        args.question = list(args.question or []) + extra
    elif extra:
        parser.error(f"unrecognized arguments: {' '.join(extra)}")

    # Must be set before helper.py is imported, since it resolves adb at import time
    if args.adb:
        if not Path(args.adb).exists():
            die(f"adb not found at '{args.adb}'", 2)
        os.environ["ADB_PATH"] = args.adb
    if args.serial:
        os.environ["ANDROID_SERIAL"] = args.serial  # honored by every adb command

    # Allow running from any working directory
    if str(BASE_DIR) not in sys.path:
        sys.path.insert(0, str(BASE_DIR))

    try:
        return args.func(args) or 0
    except KeyboardInterrupt:
        warn("Interrupted.")
        return 130


if __name__ == "__main__":
    sys.exit(main())
