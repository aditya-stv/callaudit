# forensics.py - Advanced forensic analysis functions for crime scene investigation

import pandas as pd
import numpy as np
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import networkx as nx


# ==================== TIMELINE ANALYSIS ====================

def analyze_critical_window(df, incident_datetime, hours_before=24, hours_after=24):
    """
    Analyze activity around a critical incident time.
    
    Args:
        df: Call log DataFrame
        incident_datetime: datetime of the incident
        hours_before: hours before incident to analyze
        hours_after: hours after incident to analyze
    
    Returns:
        dict with before/during/after statistics
    """
    if df.empty:
        return {}
    
    before_start = incident_datetime - timedelta(hours=hours_before)
    after_end = incident_datetime + timedelta(hours=hours_after)
    
    df_before = df[(df['datetime'] >= before_start) & (df['datetime'] < incident_datetime)]
    df_after = df[(df['datetime'] > incident_datetime) & (df['datetime'] <= after_end)]
    
    return {
        'before': {
            'count': len(df_before),
            'unique_numbers': df_before['number'].nunique(),
            'total_duration': int(df_before['duration_s'].sum()),
            'calls': df_before
        },
        'after': {
            'count': len(df_after),
            'unique_numbers': df_after['number'].nunique(),
            'total_duration': int(df_after['duration_s'].sum()),
            'calls': df_after
        },
        'incident_time': incident_datetime
    }


def detect_activity_bursts(df, window_minutes=60, threshold=5):
    """
    Detect unusual bursts of activity (many calls in short time).
    
    Args:
        df: Call log DataFrame  
        window_minutes: time window to check
        threshold: minimum calls to consider a burst
        
    Returns:
        DataFrame of detected bursts
    """
    if df.empty or 'datetime' not in df.columns:
        return pd.DataFrame()
    
    df_sorted = df.sort_values('datetime').copy()
    bursts = []
    
    for i in range(len(df_sorted)):
        window_start = df_sorted.iloc[i]['datetime']
        window_end = window_start + timedelta(minutes=window_minutes)
        
        window_calls = df_sorted[
            (df_sorted['datetime'] >= window_start) & 
            (df_sorted['datetime'] < window_end)
        ]
        
        if len(window_calls) >= threshold:
            bursts.append({
                'start_time': window_start,
                'end_time': window_end,
                'call_count': len(window_calls),
                'unique_numbers': window_calls['number'].nunique(),
                'numbers': ', '.join(window_calls['number'].unique()[:5])
            })
    
    if not bursts:
        return pd.DataFrame()
    
    burst_df = pd.DataFrame(bursts).drop_duplicates('start_time')
    return burst_df.sort_values('call_count', ascending=False)


# ==================== SOCIAL NETWORK ANALYSIS ====================

def build_contact_network(df):
    """
    Build a social network graph from call logs.
    
    Returns:
        NetworkX graph object
    """
    G = nx.Graph()
    
    if df.empty:
        return G
    
    # Get the device's own number (most common OUTGOING target or INCOMING source)
    # For now, we'll use a placeholder since we don't have device number
    device_number = "DEVICE"
    
    for _, row in df.iterrows():
        number = row['number']
        call_type = row['call_type']
        duration = row['duration_s']
        
        if not G.has_node(device_number):
            G.add_node(device_number, label="Device Owner", type="device")
        if not G.has_node(number):
            name = row.get('saved_name', '')
            G.add_node(number, label=name if name else number, type="contact")
        
        # Add or update edge
        if G.has_edge(device_number, number):
            G[device_number][number]['weight'] += 1
            G[device_number][number]['total_duration'] += duration
        else:
            G.add_edge(device_number, number, weight=1, total_duration=duration)
    
    return G


def get_network_metrics(G):
    """Calculate network centrality metrics."""
    if len(G.nodes()) == 0:
        return {}
    
    try:
        degree_centrality = nx.degree_centrality(G)
        betweenness = nx.betweenness_centrality(G)
        
        return {
            'degree_centrality': degree_centrality,
            'betweenness_centrality': betweenness,
            'total_nodes': len(G.nodes()),
            'total_edges': len(G.edges())
        }
    except:
        return {}


def identify_key_contacts(df, top_n=10):
    """
    Identify key contacts based on multiple factors.
    
    Returns:
        DataFrame with contact importance scores
    """
    if df.empty:
        return pd.DataFrame()
    
    contact_stats = df.groupby('number').agg({
        'number': 'size',
        'duration_s': ['sum', 'mean', 'max'],
        'datetime': ['min', 'max']
    }).reset_index()
    
    contact_stats.columns = ['number', 'call_count', 'total_duration', 'avg_duration', 
                            'max_duration', 'first_contact', 'last_contact']
    
    # Calculate importance score
    # Normalize each factor
    max_calls = contact_stats['call_count'].max() or 1
    max_duration = contact_stats['total_duration'].max() or 1
    
    contact_stats['frequency_score'] = contact_stats['call_count'] / max_calls
    contact_stats['duration_score'] = contact_stats['total_duration'] / max_duration
    
    # Combined importance score
    contact_stats['importance_score'] = (
        contact_stats['frequency_score'] * 0.6 +
        contact_stats['duration_score'] * 0.4
    )
    
    # Add saved names if available
    if 'saved_name' in df.columns:
        name_map = df.groupby('number')['saved_name'].first().to_dict()
        contact_stats['name'] = contact_stats['number'].map(name_map)
    
    return contact_stats.sort_values('importance_score', ascending=False).head(top_n)


# ==================== BURNER PHONE DETECTION ====================

def detect_burner_phones(df, min_calls=5, max_days=7):
    """
    Detect potential burner phones: short-lived but active numbers.
    
    Args:
        df: Call log DataFrame
        min_calls: minimum calls to consider
        max_days: maximum active days to flag as burner
        
    Returns:
        DataFrame of suspected burner phones
    """
    if df.empty:
        return pd.DataFrame()
    
    number_activity = df.groupby('number').agg({
        'datetime': ['min', 'max', 'count']
    }).reset_index()
    
    number_activity.columns = ['number', 'first_seen', 'last_seen', 'total_calls']
    number_activity['active_days'] = (number_activity['last_seen'] - number_activity['first_seen']).dt.days + 1
    
    # Burner criteria: many calls but short active period
    burners = number_activity[
        (number_activity['total_calls'] >= min_calls) &
        (number_activity['active_days'] <= max_days)
    ].copy()
    
    # Calculate suspicion score
    burners['suspicion_score'] = (burners['total_calls'] / burners['active_days']) / 10
    burners['suspicion_score'] = burners['suspicion_score'].clip(0, 1)
    
    # Add saved names if available
    if 'saved_name' in df.columns:
        name_map = df.groupby('number')['saved_name'].first().to_dict()
        burners['name'] = burners['number'].map(name_map).fillna('')
    
    return burners.sort_values('suspicion_score', ascending=False)


# ==================== CONTACT RELATIONSHIPS ====================

def analyze_contact_relationships(df):
    """
    Analyze strength of relationships with each contact.
    
    Returns:
        DataFrame with relationship metrics
    """
    if df.empty:
        return pd.DataFrame()
    
    relationships = df.groupby('number').agg({
        'number': 'size',
        'duration_s': ['sum', 'mean'],
        'call_type': lambda x: {
            'incoming': (x == 'INCOMING').sum(),
            'outgoing': (x == 'OUTGOING').sum(),
            'missed': (x == 'MISSED').sum(),
            'rejected': (x == 'REJECTED').sum()
        },
        'datetime': ['min', 'max']
    }).reset_index()
    
    relationships.columns = ['number', 'total_calls', 'total_duration', 'avg_duration',
                            'call_type_breakdown', 'first_contact', 'last_contact']
    
    # Extract call type counts
    relationships['incoming'] = relationships['call_type_breakdown'].apply(lambda x: x['incoming'])
    relationships['outgoing'] = relationships['call_type_breakdown'].apply(lambda x: x['outgoing'])
    relationships['missed'] = relationships['call_type_breakdown'].apply(lambda x: x['missed'])
    
    # Calculate relationship strength (0-100)
    max_calls = relationships['total_calls'].max() or 1
    max_duration = relationships['total_duration'].max() or 1
    
    relationships['relationship_strength'] = (
        (relationships['total_calls'] / max_calls) * 50 +
        (relationships['total_duration'] / max_duration) * 30 +
        (relationships['avg_duration'] / 300) * 20  # 300s = 5min baseline
    ).clip(0, 100)
    
    # Calculate days active
    relationships['days_active'] = (
        relationships['last_contact'] - relationships['first_contact']
    ).dt.days + 1
    
    # Add saved names
    if 'saved_name' in df.columns:
        name_map = df.groupby('number')['saved_name'].first().to_dict()
        relationships['name'] = relationships['number'].map(name_map).fillna('')
    
    return relationships.drop(columns=['call_type_breakdown']).sort_values(
        'relationship_strength', ascending=False
    )


# ==================== PATTERN DETECTION ====================

def detect_behavioral_changes(df, window_days=7):
    """
    Detect changes in communication behavior over time.
    
    Returns:
        dict with behavioral change metrics
    """
    if df.empty or len(df) < 2:
        return {}
    
    df_sorted = df.sort_values('datetime')
    
    # Split into time windows
    earliest = df_sorted['datetime'].min()
    latest = df_sorted['datetime'].max()
    total_days = (latest - earliest).days + 1
    
    if total_days < window_days * 2:
        return {'insufficient_data': True}
    
    # Compare first window vs last window
    first_window_end = earliest + timedelta(days=window_days)
    last_window_start = latest - timedelta(days=window_days)
    
    first_window = df_sorted[df_sorted['datetime'] < first_window_end]
    last_window = df_sorted[df_sorted['datetime'] >= last_window_start]
    
    return {
        'first_period': {
            'calls_per_day': len(first_window) / window_days,
            'unique_contacts': first_window['number'].nunique(),
            'avg_duration': first_window['duration_s'].mean()
        },
        'last_period': {
            'calls_per_day': len(last_window) / window_days,
            'unique_contacts': last_window['number'].nunique(),
            'avg_duration': last_window['duration_s'].mean()
        },
        'change_detected': abs(len(first_window) - len(last_window)) / max(len(first_window), 1) > 0.5
    }


def find_repeated_patterns(df):
    """
    Find repeated communication patterns (same numbers at similar times).
    
    Returns:
        DataFrame of detected patterns
    """
    if df.empty:
        return pd.DataFrame()
    
    df['hour'] = pd.to_datetime(df['datetime']).dt.hour
    
    # Find number-hour combinations that repeat
    patterns = df.groupby(['number', 'hour']).size().reset_index(name='occurrences')
    patterns = patterns[patterns['occurrences'] >= 3]  # At least 3 times
    
    if 'saved_name' in df.columns:
        name_map = df.groupby('number')['saved_name'].first().to_dict()
        patterns['name'] = patterns['number'].map(name_map).fillna('')
    
    return patterns.sort_values('occurrences', ascending=False)

# ==================== ADVANCED FORENSIC FEATURES ====================
def generate_suspect_profile(df):
    """Generate comprehensive behavioral profile from call patterns."""
    if df.empty:
        return {}
    
    total_calls = len(df)
    days_active = (df['datetime'].max() - df['datetime'].min()).days + 1
    calls_per_day = total_calls / max(days_active, 1)
    unique_contacts = df['number'].nunique()
    
    call_types = df['call_type'].value_counts()
    outgoing_ratio = call_types.get('OUTGOING', 0) / max(total_calls, 1)
    
    hour_dist = df.groupby(df['datetime'].dt.hour).size()
    peak_hour = hour_dist.idxmax() if not hour_dist.empty else 0
    
    avg_duration = df['duration_s'].mean()
    
    top_contacts = df['number'].value_counts().head(5)
    focused_communication = (top_contacts.iloc[0] / total_calls) if not top_contacts.empty else 0
    
    flags = []
    if avg_duration < 30:
        flags.append("Brief communications (possible operational)")
    if calls_per_day > 50:
        flags.append("High activity (possible business/criminal operation)")
    if outgoing_ratio > 0.8:
        flags.append("Predominantly outgoing (coordinator/leader pattern)")
    if outgoing_ratio < 0.2:
        flags.append("Predominantly incoming (receiver/follower pattern)")
    if focused_communication > 0.5:
        flags.append("Focused communication (single primary contact)")
    if unique_contacts > 100:
        flags.append("Extensive network (hub/dealer pattern)")
    
    return {
        'total_communications': total_calls,
        'active_period_days': days_active,
        'communication_frequency': calls_per_day,
        'network_size': unique_contacts,
        'outgoing_call_ratio': outgoing_ratio,
        'peak_activity_hour': peak_hour,
        'average_call_duration': avg_duration,
        'top_contact_focus': focused_communication,
        'behavioral_flags': flags
    }
def analyze_operational_security(df):
    """Analyze operational security practices based on call patterns."""
    if df.empty:
        return {}
    
    short_relationships = 0
    for number in df['number'].unique():
        number_calls = df[df['number'] == number]
        days_active = (number_calls['datetime'].max() - number_calls['datetime'].min()).days + 1
        if days_active <= 3 and len(number_calls) >= 5:
            short_relationships += 1
    
    burner_ratio = short_relationships / max(df['number'].nunique(), 1)
    hour_variance = df.groupby(df['datetime'].dt.hour).size().std()
    
    opsec_score = 0
    indicators = []
    
    if burner_ratio > 0.3:
        opsec_score += 30
        indicators.append("High burner phone usage")
    
    if hour_variance < 5:
        opsec_score += 20
        indicators.append("Consistent timing (disciplined communication)")
    
    if df['duration_s'].mean() < 60:
        opsec_score += 15
        indicators.append("Brief communications (operational discipline)")
    
    assessment = "Low"
    if opsec_score > 60:
        assessment = "High - Sophisticated operational security"
    elif opsec_score > 30:
        assessment = "Medium - Some security awareness"
    
    return {
        'opsec_score': opsec_score,
        'assessment': assessment,
        'indicators': indicators,
        'burner_ratio': burner_ratio,
        'time_variance': hour_variance
    }
def reconstruct_timeline(df, include_gaps=True):
    """Reconstruct detailed timeline of all communications."""
    if df.empty:
        return pd.DataFrame()
    
    timeline = df.copy().sort_values('datetime')
    timeline['event_type'] = 'CALL_' + timeline['call_type']
    timeline['event_description'] = timeline.apply(
        lambda row: f"{row['call_type']} call with {row.get('saved_name', row['number'])} - {row['duration']}",
        axis=1
    )
    
    if include_gaps:
        timeline['time_since_last'] = timeline['datetime'].diff()
        timeline['has_gap'] = timeline['time_since_last'] > timedelta(hours=24)
    
    return timeline[['datetime', 'event_type', 'number', 'event_description', 'duration_s']]


# ==================== SMS FORENSICS ====================

def detect_suspicious_sms(sms_df):
    """
    Scan SMS messages for suspicious indicators.
    
    Checks:
    1. Keywords: Phishing, Banking, OTP, Legal threats
    2. Links: Shortened URLs, suspicious domains
    3. Temporal: Messages during odd-night hours
    4. Identity: Masked senders (shortcodes)
    """
    if sms_df.empty:
        return pd.DataFrame()
    
    # Pre-calculated forensic indicators
    RISK_KEYWORDS = {
        'critical': ['otp', 'verify', 'login', 'unauthorized', 'access', 'blocked', 'locked', 'recover', 'pin'],
        'financial': ['bank', 'account', 'transfer', 'wired', 'debit', 'credit', 'payment', 'transaction', 'balance'],
        'threat': ['legal', 'court', 'summons', 'urgent', 'police', 'arrest', 'violation', 'penalty'],
        'phish': ['claimed', 'won', 'lottery', 'prize', 'gift', 'click', 'link', 'update', 'verify-now']
    }
    
    SHORT_URL_PATTERNS = [
        'bit.ly', 't.co', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly', 'adf.ly', 's.id'
    ]
    
    results = []
    
    # Ensure datetime exists
    df = sms_df.copy()
    if 'datetime' not in df.columns:
        df['datetime'] = pd.to_datetime(pd.to_numeric(df['date']), unit='ms', errors='coerce')
    
    for _, row in df.iterrows():
        score = 0
        reasons = []
        body = str(row.get('body', '')).lower()
        addr = str(row.get('address', '')).lower()
        
        # 1. Keyword check
        for category, keywords in RISK_KEYWORDS.items():
            matches = [k for k in keywords if k in body]
            if matches:
                weight = 0.4 if category == 'critical' else 0.2
                score += weight
                reasons.append(f"Keyword match ({category}): {', '.join(matches[:2])}")
        
        # 2. URL check
        if 'http' in body or 'www' in body:
            score += 0.3
            contains_short = any(p in body for p in SHORT_URL_PATTERNS)
            if contains_short:
                score += 0.2
                reasons.append("Suspicious shortened URL detected")
            else:
                reasons.append("Message contains web link")
                
        # 3. Identity check (Masked/Shortcode)
        if len(addr) < 8 and not addr.isdigit():
            score += 0.1
            reasons.append("Sender appears to be an automated service/shortcode")
        
        # 4. Temporal check (Odd-night: 00:00 - 05:00)
        dt = row['datetime']
        if pd.notna(dt) and 0 <= dt.hour <= 5:
            score += 0.2
            reasons.append("Night-time communication (00:00-05:00)")
            
        if score > 0:
            results.append({
                'datetime': dt,
                'address': row.get('address', ''),
                'body': row.get('body', ''),
                'type': row.get('type', ''),
                'score': min(score, 1.0),
                'reasons': ", ".join(reasons)
            })
            
    if not results:
        return pd.DataFrame()
        
    res_df = pd.DataFrame(results)
    return res_df.sort_values('score', ascending=False)
    res_df = pd.DataFrame(results)
    return res_df.sort_values('score', ascending=False)


# ==================== UNIVERSAL SYSTEM FORENSICS ====================

def detect_suspicious_apps(apps_input):
    """
    Search for apps typical of forensic interest.
    Handles both list of dicts and pandas DataFrame.
    """
    if apps_input is None:
        return pd.DataFrame(columns=['package', 'score', 'findings'])
        
    if isinstance(apps_input, list):
        if not apps_input:
            return pd.DataFrame(columns=['package', 'score', 'findings'])
        apps_df = pd.DataFrame(apps_input)
    else:
        apps_df = apps_input

    if apps_df.empty:
        return pd.DataFrame(columns=['package', 'score', 'findings'])
    
    FORENSIC_TARGETS = {
        'spyware': ['spy', 'track', 'control', 'pegasus', 'finder', 'parental'],
        'vaults': ['vault', 'hide', 'private', 'calculator', 'secret', 'secure.box', 'gallery.lock'],
        'encrypted_comms': ['signal', 'telegram', 'wickr', 'threema', 'session.id', 'whatsapp'],
        'root_tools': ['supersu', 'magisk', 'busybox', 'terminal', 'adb'],
    }
    
    results = []
    # Use 'package_name' or 'package' column if present
    pkg_col = 'package_name' if 'package_name' in apps_df.columns else 'package'
    
    for _, row in apps_df.iterrows():
        pkg = str(row.get(pkg_col, '')).lower()
        score = 0
        reasons = []
        
        # 1. Package name keyword check
        for category, keywords in FORENSIC_TARGETS.items():
            matches = [k for k in keywords if k in pkg]
            if matches:
                weight = 0.5 if category in ['spyware', 'vaults'] else 0.2
                score += weight
                reasons.append(f"Application type: {category.replace('_', ' ').title()}")
                
        # 2. Side-loading detection (Heuristic: typical non-com.android/google prefixes)
        if not any(pkg.startswith(p) for p in ['com.android', 'com.google', 'com.sec', 'com.samsung', 'com.motorola']):
            score += 0.1
            reasons.append("Non-standard package prefix (possible sideload)")

        if score > 0:
            results.append({
                'package': pkg,
                'score': min(score, 1.0),
                'findings': ", ".join(reasons)
            })
            
    if not results:
        return pd.DataFrame(columns=['package', 'score', 'findings'])
        
    return pd.DataFrame(results).sort_values('score', ascending=False)


def analyze_system_security_logs(logcat_raw):
    """Scan logcat for critical security events."""
    if not logcat_raw:
        return []
    
    SECURITY_PATTERNS = {
        'ROOT_ATTEMPT': r'(su|superuser|root)',
        'DEBUG_ACTIVE': r'(adb|debugging|usb_debug)',
        'SYSTEM_RESET': r'(reboot|shutdown|boot_complete)',
        'FAILED_AUTH': r'(authentication_failed|wrong_password|fingerprint_error)',
        'ENCRYPTION': r'(crypt|vault|mount_point)'
    }
    
    import re
    findings = []
    lines = logcat_raw.splitlines()
    for i, line in enumerate(lines):
        line_lower = line.lower()
        for cat, pattern in SECURITY_PATTERNS.items():
            if re.search(pattern, line_lower):
                findings.append({
                    'category': cat,
                    'line_no': i,
                    'content': line[:200] # Cap length
                })
    return findings


def detect_network_anomalies(wifi_raw, browser_searches):
    """Flag risky networks and suspicious search intent."""
    anomalies = []
    
    # WiFi Analysis
    if wifi_raw:
        if "NONE" in wifi_raw or "OPEN" in wifi_raw:
            anomalies.append("Historical connection to unsecured/OPEN WiFi detected.")
            
    # Search Intent
    LOW_OPSEC_KEYWORDS = ['buy guns', 'how to delete logs', 'clear adb', 'wipe phone', 'fake gps', 'hide location', 'vpn for anonymous']
    if browser_searches:
        found_keywords = [k for k in LOW_OPSEC_KEYWORDS if k in browser_searches.lower()]
        if found_keywords:
            anomalies.append(f"Critical Search Intent: {', '.join(found_keywords)}")
            
    return anomalies


def analyze_account_risks(accounts_raw):
    """Identify multiple accounts or privacy-focused services."""
    if not accounts_raw:
        return []
    
    findings = []
    import re
    
    # 1. Persona Splitting (Multiple Google Accounts)
    google_accounts = re.findall(r'Account {name=([^,]+), type=com.google}', accounts_raw)
    if len(google_accounts) > 1:
        findings.append({
            'category': 'Persona Splitting',
            'detail': f"Multiple Google identities detected: {', '.join(google_accounts)}."
        })
        
    # 2. Privacy & Evasion Apps
    PRIVACY_TYPES = {
        'com.signal.id': 'Signal (Encrypted)',
        'com.protonmail': 'Proton (Secure Mail)',
        'org.torproject': 'Tor/Orbot (Anonymity)',
        'com.telegram': 'Telegram (Messaging)'
    }
    for p_type, label in PRIVACY_TYPES.items():
        if p_type in accounts_raw.lower():
            findings.append({'category': 'Privacy/Evasion', 'detail': f"Secure platform '{label}' configured."})

    # 3. Financial & Crypto Footprint
    FINANCE_TYPES = ['binance', 'coinbase', 'crypto', 'revolut', 'paypal', 'venmo']
    found_fin = [f.title() for f in FINANCE_TYPES if f in accounts_raw.lower()]
    if found_fin:
        findings.append({'category': 'Financial/Crypto', 'detail': f"Active financial hooks: {', '.join(found_fin)}."})

    # 4. Lifestyle/Secret Personas (Dating)
    LIFESTYLE_TYPES = ['tinder', 'bumble', 'grindr', 'badoo', 'okcupid']
    found_life = [l.title() for l in LIFESTYLE_TYPES if l in accounts_raw.lower()]
    if found_life:
        findings.append({'category': 'Lifestyle/Social', 'detail': f"Profiles detected on sensitive social platforms: {', '.join(found_life)}."})
        
    return findings


def parse_account_details(accounts_raw):
    """
    Parse raw dumpsys account into a structured DataFrame.
    """
    if not accounts_raw:
        return pd.DataFrame()
    
    import re
    # Pattern: Account {name=..., type=...}
    matches = re.findall(r'Account {name=([^,]+), type=([^}]+)}', accounts_raw)
    
    results = []
    for name, a_type in matches:
        category = "Other"
        a_type_low = a_type.lower()
        
        if 'google' in a_type_low: category = "Google/System"
        elif any(x in a_type_low for x in ['facebook', 'whatsapp', 'instagram', 'twitter', 'linkedin', 'telegram', 'signal']):
            category = "Social/Comms"
        elif any(x in a_type_low for x in ['bank', 'crypto', 'paypal', 'coinbase', 'binance', 'revolut']):
            category = "Finance"
        elif any(x in a_type_low for x in ['email', 'exchange', 'proton', 'outlook']):
            category = "Identity/Mail"
            
        results.append({
            'name': name,
            'type': a_type,
            'category': category
        })
        
    return pd.DataFrame(results)


# ==================== CONNECTIVITY & NETWORK DEEP FORENSICS ====================

def parse_wifi_profiles(wifi_raw):
    """
    Parse SSIDs and security types from dumpsys wifi.
    Useful for identifying frequented locations.
    """
    if not wifi_raw:
        return pd.DataFrame()
    
    import re
    # Extract SSIDs (typically found in 'Configured networks' section)
    # Pattern looks for SSID: "NAME"
    ssids = re.findall(r'SSID: "([^"]+)"', wifi_raw)
    security = re.findall(r'KeyMgmt: ([^\s]+)', wifi_raw)
    
    results = []
    for i in range(len(ssids)):
        results.append({
            'ssid': ssids[i],
            'security': security[i] if i < len(security) else "Unknown"
        })
        
    return pd.DataFrame(results).drop_duplicates('ssid') if results else pd.DataFrame()


def analyze_bluetooth_pairings(bt_raw):
    """
    Parse paired Bluetooth devices from dumpsys bluetooth_manager.
    Identifies links to other hardware (cars, phones, IoT).
    """
    if not bt_raw:
        return []
    
    import re
    # Pattern for paired devices: Name: [NAME], Address: [MAC]
    devices = re.findall(r'Name: ([^,]+), Address: ([0-9A-F:]+)', bt_raw)
    
    findings = []
    for name, addr in devices:
        category = "Other"
        n = name.lower()
        if any(w in n for w in ['car', 'toyota', 'honda', 'ford', 'sync', 'bmw', 'audi', 'tesla']):
            category = "Vehicle"
        elif any(w in n for w in ['phone', 'iphone', 'galaxy', 'android', 'pixel']):
            category = "Mobile Phone"
        elif any(w in n for w in ['watch', 'airpods', 'buds', 'headphones', 'ear']):
            category = "Wearable"
            
        findings.append({
            'name': name.strip(),
            'address': addr,
            'category': category
        })
    return findings


def analyze_browser_domains(browser_searches):
    """
    Categorize search domains to profile user interests.
    """
    if not browser_searches:
        return pd.DataFrame()
    
    import re
    # Extract domains from text (very basic heuristic)
    domains = re.findall(r'(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]', browser_searches.lower())
    
    domain_counts = Counter(domains)
    results = []
    
    CATEGORIES = {
        'Social/Comms': ['facebook', 'twitter', 'instagram', 'linkedin', 'reddit', 'whatsapp', 'telegram'],
        'Finance/Bank': ['bank', 'paypal', 'crypto', 'binance', 'coinbase', 'chase', 'wellsfargo'],
        'Privacy/Evasion': ['vpn', 'tor', 'proxy', 'duckduckgo', 'protonmail', 'incognito', 'dark'],
        'Shopping': ['amazon', 'ebay', 'walmart', 'target', 'shop'],
        'Info/Research': ['wikipedia', 'github', 'stackoverflow', 'medium', 'news']
    }
    
    for domain, count in domain_counts.items():
        category = "General"
        for cat, domains_list in CATEGORIES.items():
            if any(d in domain for d in domains_list):
                category = cat
                break
        
        results.append({
            'domain': domain,
            'count': count,
            'category': category
        })
        
    if not results:
        return pd.DataFrame(columns=['domain', 'count', 'category'])
        
    return pd.DataFrame(results).sort_values('count', ascending=False)


# ==================== USAGE & NETWORK DATA FORENSICS ====================

def parse_app_usage_stats(usagestats_raw):
    """
    Parse app foreground time and session counts from dumpsys usagestats.
    """
    if not usagestats_raw:
        return pd.DataFrame()
    
    import re
    # Look for package rows: package=com.android.chrome totalTime="1:23:45" lastTime="..."
    # Note: dumpsys output varies by Android version, using a generic pattern
    packages = re.findall(r'package=([^\s]+)', usagestats_raw)
    times = re.findall(r'totalTime="([^"]+)"', usagestats_raw)
    
    results = []
    for i in range(min(len(packages), len(times))):
        time_str = times[i]
        # Convert HH:MM:SS to seconds
        seconds = 0
        try:
            parts = time_str.split(':')
            if len(parts) == 3:
                seconds = int(parts[0])*3600 + int(parts[1])*60 + int(parts[2])
            elif len(parts) == 2:
                seconds = int(parts[0])*60 + int(parts[1])
        except Exception:
            pass
            
        results.append({
            'package': packages[i],
            'foreground_time_sec': seconds,
            'time_display': time_str
        })
        
    return pd.DataFrame(results).sort_values('foreground_time_sec', ascending=False).head(20) if results else pd.DataFrame()


def parse_network_data_usage(netstats_raw):
    """
    Examine network Rx/Tx bytes per UID from dumpsys netstats.
    Identifies high-data applications (potential exfiltration).
    """
    if not netstats_raw:
        return pd.DataFrame()
    
    import re
    # Patterns for UID traffic entries
    # uid=10123 set=DEFAULT tag=0x0 rxBytes=123 txBytes=456
    uids = re.findall(r'uid=(\d+)', netstats_raw)
    rx = re.findall(r'rxBytes=(\d+)', netstats_raw)
    tx = re.findall(r'txBytes=(\d+)', netstats_raw)
    
    results = []
    # Netstats often contains duplicates per interface, we will aggregate by UID
    uid_traffic = {}
    
    for i in range(min(len(uids), len(rx), len(tx))):
        uid = uids[i]
        r = int(rx[i])
        t = int(tx[i])
        
        if uid not in uid_traffic:
            uid_traffic[uid] = {'rx': 0, 'tx': 0}
        uid_traffic[uid]['rx'] += r
        uid_traffic[uid]['tx'] += t
        
    for uid, traffic in uid_traffic.items():
        results.append({
            'uid': uid,
            'rx_mb': round(traffic['rx'] / (1024 * 1024), 2),
            'tx_mb': round(traffic['tx'] / (1024 * 1024), 2),
            'total_mb': round((traffic['rx'] + traffic['tx']) / (1024 * 1024), 2)
        })
    
    # Return empty DataFrame with proper columns if no results
    if not results:
        return pd.DataFrame(columns=['uid', 'rx_mb', 'tx_mb', 'total_mb'])
    
    return pd.DataFrame(results).sort_values('total_mb', ascending=False)


def detect_usage_anomaly_alerts(usagestats_raw, netstats_df, batterystats_raw=""):
    """
    Perform deep forensic analysis on raw dumps to find stealthy or suspicious activity.
    """
    alerts = []
    
    # 1. Exfiltration Indicators (Tx/Rx Ratio)
    if not netstats_df.empty:
        # Avoid division by zero
        df = netstats_df.copy()
        df['ratio'] = df['tx_mb'] / df['rx_mb'].replace(0, 0.001)
        outliers = df[df['ratio'] > 2.0]
        for _, row in outliers.iterrows():
            if row['total_mb'] > 1.0: # Ignore tiny traffic
                alerts.append({
                    'category': 'Exfiltration Risk',
                    'package': row['uid'],
                    'details': f"Tx/Rx ratio is {row['ratio']:.2f}. Sent {row['tx_mb']}MB vs Received {row['rx_mb']}MB."
                })

    # 2. Insomnia Activity (Nighttime usage 00:00 - 05:00)
    if usagestats_raw:
        import re
        # Look for full timestamps in dumpsys (often in 'Events' section)
        # Format: 2024-01-01 02:30:15
        night_events = re.findall(r'(\d{4}-\d{2}-\d{2})\s(0[0-4]:\d{2}:\d{2})', usagestats_raw)
        if night_events:
            alerts.append({
                'category': 'Insomnia Activity',
                'package': 'Multiple (Check Events)',
                'details': f"Detected {len(night_events)} system events during red-zone hours (00:00 - 05:00)."
            })

    # 3. Battery Vampire (High radio vs Low usage)
    if batterystats_raw:
        # Heuristic: Apps using mobile radio for long periods without being in foreground
        # Pattern varies, but we look for high 'mobile_radio_active' time
        radio_users = re.findall(r'Uid (\d+):.*mobile_radio_active=(\d+)', batterystats_raw)
        for uid, r_time in radio_users:
            ms = int(r_time)
            if ms > 300000: # > 5 minutes of active radio
                alerts.append({
                    'category': 'Stealth Communication',
                    'package': uid,
                    'details': f"High background radio activity detected ({round(ms/60000, 1)} mins)."
                })
                
    return alerts
