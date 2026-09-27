# preprocessor.py
import pandas as pd
from datetime import datetime
from helper import parse_content_query, fetch_call_log_raw, normalize_phone_number
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import IsolationForest
import numpy as np

# mapping typical Android type codes
TYPE_MAP = {"1": "INCOMING", "2": "OUTGOING", "3": "MISSED", "5": "REJECTED", "0": "UNKNOWN"}


def ms_to_dt(ms):
    """Convert milliseconds since epoch to a naive datetime or pd.NaT on failure."""
    try:
        if ms is None or ms == "" or pd.isna(ms):
            return pd.NaT
        s = int(ms) / 1000.0
        return datetime.fromtimestamp(s)
    except Exception:
        return pd.NaT


def sec_to_hms(s):
    """Convert seconds (int or str) to HH:MM:SS string."""
    try:
        s = int(s)
    except Exception:
        return "00:00:00"
    h = s // 3600
    m = (s % 3600) // 60
    sec = s % 60
    return f"{h:02d}:{m:02d}:{sec:02d}"


# -----------------------
# Normalization
# -----------------------
def normalize_dataframe(rows):
    """
    Convert list-of-dicts (rows from parse_content_query) into a cleaned DataFrame.

    Returns columns:
      number, call_type, duration_s, duration, datetime, hour, date, weekday, name (from call log)
    """
    if not rows:
        return pd.DataFrame(columns=["number", "name", "call_type", "duration_s", "duration", "datetime", "hour", "date", "weekday"])

    df = pd.DataFrame(rows)

    # Extract name from call log (many call logs store the contact name)
    if "name" in df.columns:
        df["name_from_log"] = df["name"].astype(str).replace("", pd.NA).replace("NULL", pd.NA)
    else:
        df["name_from_log"] = pd.NA
    
    # Also check other possible name fields
    for alt_name in ("cached_name", "formatted_name", "display_name"):
        if alt_name in df.columns:
            df["name_from_log"] = df["name_from_log"].fillna(
                df[alt_name].astype(str).replace("", pd.NA).replace("NULL", pd.NA)
            )

    # normalize phone number column from several possible names
    for alt in ("number", "normalized_number", "formatted_number", "matched_number", "data1"):
        if alt in df.columns:
            df = df.rename(columns={alt: "number"})
            break
    if "number" not in df.columns:
        df["number"] = ""

    # duration (seconds)
    if "duration" in df.columns:
        df["duration_s"] = pd.to_numeric(df["duration"], errors="coerce").fillna(0).astype(int)
    else:
        df["duration_s"] = 0

    # timestamp in ms
    if "date" in df.columns:
        df["timestamp_ms"] = pd.to_numeric(df["date"], errors="coerce")
    elif "last_modified" in df.columns:
        df["timestamp_ms"] = pd.to_numeric(df["last_modified"], errors="coerce")
    else:
        df["timestamp_ms"] = pd.NA

    df["datetime"] = df["timestamp_ms"].apply(ms_to_dt)
    df["duration"] = df["duration_s"].apply(sec_to_hms)

    # call type mapping
    if "type" in df.columns:
        df["call_type"] = df["type"].astype(str).map(TYPE_MAP).fillna("UNKNOWN")
    elif "phone_call_type" in df.columns:
        df["call_type"] = df["phone_call_type"].astype(str).map(TYPE_MAP).fillna("UNKNOWN")
    else:
        df["call_type"] = "UNKNOWN"

    # derived columns
    df["hour"] = df["datetime"].apply(lambda d: d.hour if not pd.isna(d) else pd.NA)
    df["date"] = df["datetime"].apply(lambda d: d.date() if not pd.isna(d) else pd.NaT)
    df["weekday"] = df["datetime"].apply(lambda d: d.weekday() if not pd.isna(d) else pd.NA)

    # normalize number - use centralized function for consistent matching
    df["number_raw"] = df["number"].astype(str).str.strip()
    df["number"] = df["number_raw"].apply(normalize_phone_number)

    out = df[["number", "name_from_log", "call_type", "duration_s", "duration", "datetime", "hour", "date", "weekday"]].copy()
    out = out.rename(columns={"name_from_log": "name"})
    out = out.sort_values("datetime", ascending=False).reset_index(drop=True)
    return out


# -----------------------
# Analysis helpers
# -----------------------
def most_frequent(df, top_n=10):
    """Return top_n most frequent numbers with counts."""
    if df.empty:
        return pd.DataFrame(columns=["number", "count"])
    freq = df["number"].value_counts().reset_index()
    freq.columns = ["number", "count"]
    return freq.head(top_n)


def calls_by_hour(df):
    """Return pivot table of calls by hour and call_type (hour x call_type)."""
    if df.empty:
        return pd.DataFrame()
    pivot = df.groupby(["hour", "call_type"]).size().unstack(fill_value=0)
    pivot = pivot.reset_index().sort_values("hour")
    return pivot


def calls_per_day(df):
    """Return DataFrame with columns ['date','count'] for calls grouped by date."""
    if df.empty:
        return pd.DataFrame()
    s = df.groupby("date").size().reset_index(name="count").sort_values("date")
    return s


def calls_heatmap(df):
    """
    Return pivot table (hours x weekdays) suitable for heatmap plotting.
    Rows: hour 0..23, Columns: weekday 0..6
    """
    if df.empty:
        return pd.DataFrame()
    pivot = df.groupby(["hour", "weekday"]).size().unstack(fill_value=0)
    # ensure hours 0..23 exist
    for h in range(0, 24):
        if h not in pivot.index:
            pivot.loc[h] = [0] * (7 if 6 in pivot.columns else pivot.shape[1])
    pivot = pivot.sort_index()
    # ensure weekday columns 0..6
    for w in range(0, 7):
        if w not in pivot.columns:
            pivot[w] = 0
    pivot = pivot[[0, 1, 2, 3, 4, 5, 6]].fillna(0)
    return pivot


# -----------------------
# Caller aggregates and clustering
# -----------------------
def caller_features(df):
    """Aggregate caller-level features for clustering/analysis."""
    if df.empty:
        return pd.DataFrame()
    agg = df.groupby("number").agg(
        total_calls=("number", "size"),
        avg_duration=("duration_s", "mean"),
        total_duration=("duration_s", "sum"),
        missed_calls=("call_type", lambda s: (s == "MISSED").sum()),
    ).reset_index()
    agg["pct_missed"] = agg["missed_calls"] / agg["total_calls"]
    return agg


def cluster_callers(agg_df, k=3):
    """Cluster callers using KMeans on aggregated features. Returns agg_df with cluster and cluster_dist."""
    if agg_df.empty:
        return agg_df
    X = agg_df[["total_calls", "avg_duration", "pct_missed"]].fillna(0).values
    scaler = StandardScaler()
    Xs = scaler.fit_transform(X)
    k = max(1, min(k, Xs.shape[0]))
    kmeans = KMeans(n_clusters=k, random_state=42)
    labels = kmeans.fit_predict(Xs)
    agg = agg_df.copy()
    agg["cluster"] = labels
    centers = kmeans.cluster_centers_
    dists = np.linalg.norm(Xs - centers[labels], axis=1)
    agg["cluster_dist"] = dists
    return agg


# -----------------------
# Heuristic suspicious detection
# -----------------------
def heuristic_suspicious(
    df,
    night_start=0,
    night_end=5,
    long_call_threshold_s=3600,
    frequent_window_minutes=30,
    frequent_calls_threshold=5,
    short_call_seconds=10,
):
    """
    Heuristic rules:
      - Long calls (>= long_call_threshold_s)
      - Calls during odd night hours (night_start..night_end)
      - Frequent short calls within frequent_window_minutes
    Returns DataFrame with columns ['number','datetime','call_type','duration_s','reason','score'].
    """
    suspicious = []
    if df.empty:
        return pd.DataFrame(columns=["number", "datetime", "call_type", "duration_s", "reason", "score"])

    # Long call & night call rules
    for idx, row in df.iterrows():
        score = 0.0
        reasons = []
        if row["duration_s"] >= long_call_threshold_s:
            reasons.append("Long call")
            score += 0.6
        if row["hour"] is not pd.NA and isinstance(row["hour"], (int, float)):
            h = int(row["hour"])
            if (night_start <= h <= night_end) and row["duration_s"] > 0:
                reasons.append("Odd-night call")
                score += 0.4
        if reasons:
            suspicious.append(
                {
                    "number": row["number"],
                    "datetime": row["datetime"],
                    "call_type": row["call_type"],
                    "duration_s": row["duration_s"],
                    "reason": "; ".join(reasons),
                    "score": min(score, 1.0),
                }
            )

    # Frequent short calls detection (sliding window per number)
    df_ts = df.dropna(subset=["datetime"]).sort_values("datetime")
    if not df_ts.empty:
        for number, group in df_ts.groupby("number"):
            times = list(group["datetime"])
            durations = list(group["duration_s"])
            i = 0
            n = len(times)
            while i < n:
                j = i
                window_calls = 1
                window_durations = durations[i]
                while j + 1 < n and (times[j + 1] - times[i]).total_seconds() <= frequent_window_minutes * 60:
                    j += 1
                    window_calls += 1
                    window_durations += durations[j]
                if window_calls >= frequent_calls_threshold and (window_durations / window_calls) <= short_call_seconds:
                    for k in range(i, j + 1):
                        suspicious.append(
                            {
                                "number": number,
                                "datetime": times[k],
                                "call_type": df_ts.iloc[k]["call_type"],
                                "duration_s": df_ts.iloc[k]["duration_s"],
                                "reason": f"Frequent short calls ({window_calls} in {frequent_window_minutes}m)",
                                "score": 0.7,
                            }
                        )
                i += 1

    sus_df = pd.DataFrame(suspicious)
    if sus_df.empty:
        return sus_df
    sus_df = sus_df.drop_duplicates(subset=["number", "datetime"]).sort_values("score", ascending=False).reset_index(drop=True)
    return sus_df


# -----------------------
# Isolation Forest anomalies
# -----------------------
def isolation_anomalies(df, contamination=0.05):
    """
    Unsupervised anomaly detection using IsolationForest on per-call features.
    Returns DataFrame of flagged anomalies with anomaly_score (0..1, higher = more anomalous).
    """
    if df.empty:
        return pd.DataFrame()
    tmp = df.copy()
    tmp["dayofweek"] = tmp["datetime"].apply(lambda d: d.weekday() if pd.notna(d) else -1)
    freq = tmp["number"].value_counts().to_dict()
    tmp["count_by_number"] = tmp["number"].map(freq).fillna(0)

    X = tmp[["duration_s", "hour", "dayofweek", "count_by_number"]].fillna(-1).astype(float).values
    if X.shape[0] < 5:
        return pd.DataFrame()

    iso = IsolationForest(n_estimators=100, contamination=contamination, random_state=42)
    preds = iso.fit_predict(X)
    raw_scores = iso.decision_function(X)  # higher = less anomalous

    # Normalize raw_scores into anomaly_score in 0..1 where 1 is most anomalous
    smax = float(np.max(raw_scores))
    smin = float(np.min(raw_scores))
    denom = smax - smin if (smax - smin) != 0 else 1.0
    anomaly_score = (smax - raw_scores) / denom

    tmp["anomaly_score"] = anomaly_score
    tmp["anomaly_flag"] = preds == -1
    res = tmp[tmp["anomaly_flag"]].copy()
    if res.empty:
        return res
    res = res[["number", "datetime", "call_type", "duration_s", "anomaly_score"]].sort_values("anomaly_score", ascending=False)
    return res


# -----------------------
# Forecasting calls-per-day
# -----------------------
def forecast_calls_per_day(series_df, days_ahead=7):
    """
    Forecast calls-per-day.
    Input: series_df with columns ['date','count'] where date is datetime.date
    Returns combined DataFrame with historical + forecast rows and optional lower/upper.
    """
    import pandas as pd

    if series_df.empty:
        return pd.DataFrame()

    ts = series_df.copy()
    ts["date"] = pd.to_datetime(ts["date"])
    ts = ts.set_index("date").asfreq("D").fillna(0)
    y = ts["count"].astype(float)

    try:
        from statsmodels.tsa.arima.model import ARIMA

        model = ARIMA(y, order=(1, 1, 0))
        fit = model.fit()
        pred = fit.get_forecast(steps=days_ahead)
        mean = pred.predicted_mean
        ci = pred.conf_int(alpha=0.05)

        future_idx = pd.date_range(start=y.index[-1] + pd.Timedelta(days=1), periods=days_ahead, freq="D")
        fc = pd.DataFrame(
            {"date": future_idx, "count": mean.values, "lower": ci.iloc[:, 0].values, "upper": ci.iloc[:, 1].values}
        ).set_index("date")

        existing = pd.DataFrame({"date": y.index, "count": y.values}).set_index("date")
        out = pd.concat([existing, fc], axis=0).reset_index()
        out["date"] = out["date"].dt.date
        out["lower"] = out.get("lower", out["count"])
        out["upper"] = out.get("upper", out["count"])
        return out.reset_index(drop=True)

    except Exception:
        # fallback: linear regression on index
        from sklearn.linear_model import LinearRegression

        idx = np.arange(len(y)).reshape(-1, 1)
        model = LinearRegression()
        model.fit(idx, y.values)
        future_idx = np.arange(len(y), len(y) + days_ahead).reshape(-1, 1)
        preds = model.predict(future_idx)
        future_dates = pd.date_range(start=y.index[-1] + pd.Timedelta(days=1), periods=days_ahead, freq="D")
        out_existing = pd.DataFrame({"date": y.index.date, "count": y.values})
        out_future = pd.DataFrame({"date": future_dates.date, "count": preds, "lower": preds * 0.9, "upper": preds * 1.1})
        out = pd.concat([out_existing, out_future], axis=0).reset_index(drop=True)
        return out


# -----------------------
# Natural-language summaries
# -----------------------
def generate_nl_most_frequent(freq_df):
    if freq_df.empty:
        return "No callers found."
    top = freq_df.iloc[0]
    number = top["number"]
    count = int(top["count"])
    others = int(freq_df["count"].iloc[1:4].sum()) if len(freq_df) > 1 else 0
    return f"Most frequent caller: {number} called {count} times. Next top callers total {others} calls."


def generate_nl_hourly(df):
    if df.empty:
        return "No hourly data."
    pivot = df.groupby("hour").size()
    if pivot.empty:
        return "No hourly calls."
    peak = int(pivot.idxmax())
    peak_count = int(pivot.max())
    return f"Peak calling hour: {peak:02d}:00 with {peak_count} calls."


def generate_nl_forecast(forecast_df, days=7):
    if forecast_df.empty:
        return "No forecast available."
    tail = forecast_df.tail(days)
    mean = float(tail["count"].mean())
    std = float(tail["count"].std(ddof=0)) if len(tail) > 1 else 0.0
    return f"Next {days}-day forecast (mean±std): {mean:.1f} ± {std:.1f} calls/day."


def generate_nl_heuristic(sus_df):
    if sus_df.empty:
        return "No heuristic suspicious activities detected."
    top = sus_df.iloc[0]
    num = top["number"]
    reason = top["reason"]
    return f"Top heuristic alert: {num} — {reason}."


def generate_nl_ai(anom_df):
    if anom_df.empty:
        return "No AI anomalies detected."
    top = anom_df.iloc[0]
    num = top["number"]
    score = float(top["anomaly_score"])
    return f"Top AI anomaly: {num} (score {score:.2f})."


def generate_nl_clustering(clustered_df):
    if clustered_df.empty:
        return "Not enough data for clustering."
    grp = clustered_df.groupby("cluster")["total_calls"].mean().sort_values(ascending=False)
    top_cluster = int(grp.index[0])
    return f"Cluster {top_cluster} has highest average calls per contact."


# --- Device info normalize ---
def normalize_device_props(raw):
    """
    Parse `adb shell getprop` output lines like:
      [ro.build.version.sdk]: [30]
    into a dict {key: value}
    """
    out = {}
    if not raw:
        return out
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue
        # Expected format: [key]: [value]
        if line.startswith("[") and "]: [" in line:
            try:
                k, v = line.split("]: [", 1)
                k = k.lstrip("[").strip()
                v = v.rstrip("]").strip()
                out[k] = v
            except Exception:
                # fallback: attempt to split on ':' once
                parts = line.split(":", 1)
                if len(parts) == 2:
                    out[parts[0].strip().strip("[]")] = parts[1].strip().strip("[]")
        else:
            # permissive fallback
            if ":" in line:
                k, v = line.split(":", 1)
                out[k.strip().strip("[]")] = v.strip().strip("[]")
    return out


def parse_battery(raw):
    """Parse dumpsys battery output into a simple dict of key -> value."""
    data = {}
    if not raw:
        return data
    for line in raw.splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            data[k.strip()] = v.strip()
    return data


def extract_potential_owner_name(accounts_raw=None, profile_raw=None):
    """
    Attempt to identify the device owner from accounts or contact profile.
    
    Returns:
        str: Potential owner name or "Unknown"
    """
    potential_names = []
    
    # 1. Try Contact Profile (Me profile)
    if profile_raw:
        rows = parse_content_query(profile_raw)
        for row in rows:
            for field in ["display_name", "name", "data1"]:
                if field in row and row[field] and row[field].upper() != "NULL":
                    name = row[field].strip()
                    if name and "@" not in name: # Prefer names over emails here
                        return name
                    elif name:
                        potential_names.append(name)

    # 2. Try Accounts (dumpsys account)
    if accounts_raw:
        import re
        # Look for name field in Account {name=..., type=...}
        matches = re.findall(r'Account \{name=([^,]+),', accounts_raw)
        for match in matches:
            if match and match.upper() != "NULL":
                name = match.strip()
                # If it's an email, we keep it as a fallback
                if "@" in name:
                    potential_names.append(name.split("@")[0].title().replace(".", " "))
                else:
                    return name # High confidence if it's a non-email account name
    
    if potential_names:
        return potential_names[0]
        
    return "Unknown"
