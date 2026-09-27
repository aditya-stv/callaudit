# forensic_extractors.py - Additional forensic data extraction functions

import subprocess
from typing import List, Dict
from helper import run_adb_cmd, parse_content_query

# ============================================================================
# SMS/MMS EXTRACTION
# ============================================================================

def fetch_sms_raw() -> str:
    """Fetch all SMS messages using content provider query."""
    return run_adb_cmd([
        "shell", "content", "query",
        "--uri", "content://sms"
    ], timeout=90)


def fetch_sms_inbox() -> str:
    """Fetch only inbox SMS messages."""
    return run_adb_cmd([
        "shell", "content", "query",
        "--uri", "content://sms/inbox"
    ], timeout=60)


def fetch_sms_sent() -> str:
    """Fetch only sent SMS messages."""
    return run_adb_cmd([
        "shell", "content", "query",
        "--uri", "content://sms/sent"
    ], timeout=60)


def fetch_sms_conversations() -> str:
    """Fetch SMS conversation threads."""
    return run_adb_cmd([
        "shell", "content", "query",
        "--uri", "content://sms/conversations"
    ], timeout=60)


def fetch_mms_raw() -> str:
    """Fetch MMS messages (multimedia messages)."""
    return run_adb_cmd([
        "shell", "content", "query",
        "--uri", "content://mms"
    ], timeout=90)


# ============================================================================
# ENHANCED CONTACT EXTRACTION
# ============================================================================

def fetch_contacts_full() -> str:
    """Fetch comprehensive contact information including emails, addresses, etc."""
    return run_adb_cmd([
        "shell", "content", "query",
        "--uri", "content://com.android.contacts/data"
    ], timeout=90)


def fetch_contacts_emails() -> str:
    """Fetch only email addresses from contacts."""
    return run_adb_cmd([
        "shell", "content", "query",
        "--uri", "content://com.android.contacts/data/emails"
    ], timeout=60)


def fetch_contacts_addresses() -> str:
    """Fetch physical addresses from contacts."""
    return run_adb_cmd([
        "shell", "content", "query",
        "--uri", "content://com.android.contacts/data/postal_addresses"
    ], timeout=60)


# ============================================================================
# BROWSER HISTORY EXTRACTION
# ============================================================================

def fetch_browser_bookmarks() -> str:
    """Fetch browser bookmarks."""
    return run_adb_cmd([
        "shell", "content", "query",
        "--uri", "content://browser/bookmarks"
    ], timeout=60)


def fetch_browser_searches() -> str:
    """Fetch browser search history."""
    return run_adb_cmd([
        "shell", "content", "query",
        "--uri", "content://browser/searches"
    ], timeout=60)


# ============================================================================
# CALENDAR EVENTS EXTRACTION
# ============================================================================

def fetch_calendar_events() -> str:
    """Fetch calendar events."""
    return run_adb_cmd([
        "shell", "content", "query",
        "--uri", "content://com.android.calendar/events"
    ], timeout=90)


def fetch_calendar_attendees() -> str:
    """Fetch calendar event attendees."""
    return run_adb_cmd([
        "shell", "content", "query",
        "--uri", "content://com.android.calendar/attendees"
    ], timeout=60)


# ============================================================================
# APP USAGE & SYSTEM INFORMATION
# ============================================================================

def fetch_installed_packages() -> str:
    """Fetch list of all installed packages/apps."""
    return run_adb_cmd([
        "shell", "pm", "list", "packages", "-f"
    ], timeout=60)


def fetch_app_usage_stats() -> str:
    """Fetch app usage statistics."""
    return run_adb_cmd([
        "shell", "dumpsys", "usagestats"
    ], timeout=90)


def fetch_battery_stats() -> str:
    """Fetch battery usage statistics (includes app usage)."""
    return run_adb_cmd([
        "shell", "dumpsys", "batterystats"
    ], timeout=90)


def fetch_recent_apps() -> str:
    """Fetch recently used apps."""
    return run_adb_cmd([
        "shell", "dumpsys", "activity", "recents"
    ], timeout=60)


# ============================================================================
# LOCATION & NETWORK DATA
# ============================================================================

def fetch_location_data() -> str:
    """Fetch location services data."""
    return run_adb_cmd([
        "shell", "dumpsys", "location"
    ], timeout=60)


def fetch_wifi_networks() -> str:
    """Fetch configured WiFi networks."""
    try:
        return run_adb_cmd([
            "shell", "cmd", "wifi", "list-networks"
        ], timeout=30)
    except Exception:
        # Fallback for older Android versions
        return run_adb_cmd([
            "shell", "dumpsys", "wifi"
        ], timeout=60)


def fetch_bluetooth_devices() -> str:
    """Fetch paired Bluetooth devices."""
    return run_adb_cmd([
        "shell", "dumpsys", "bluetooth_manager"
    ], timeout=30)


def fetch_network_stats() -> str:
    """Fetch network usage statistics."""
    return run_adb_cmd([
        "shell", "dumpsys", "netstats"
    ], timeout=60)


# ============================================================================
# MEDIA & DOWNLOADS
# ============================================================================

def fetch_media_images() -> str:
    """Fetch image file metadata."""
    return run_adb_cmd([
        "shell", "content", "query",
        "--uri", "content://media/external/images/media"
    ], timeout=90)


def fetch_media_videos() -> str:
    """Fetch video file metadata."""
    return run_adb_cmd([
        "shell", "content", "query",
        "--uri", "content://media/external/video/media"
    ], timeout=90)


def fetch_media_audio() -> str:
    """Fetch audio file metadata."""
    return run_adb_cmd([
        "shell", "content", "query",
        "--uri", "content://media/external/audio/media"
    ], timeout=90)


def fetch_downloads() -> str:
    """Fetch download history."""
    return run_adb_cmd([
        "shell", "content", "query",
        "--uri", "content://downloads/my_downloads"
    ], timeout=60)


# ============================================================================
# SYSTEM LOGS & ACCOUNTS
# ============================================================================

def fetch_logcat() -> str:
    """Fetch system log (logcat)."""
    return run_adb_cmd([
        "logcat", "-d", "-t", "1000"  # Last 1000 lines
    ], timeout=60)


def fetch_accounts() -> str:
    """Fetch account information."""
    return run_adb_cmd([
        "shell", "dumpsys", "account"
    ], timeout=60)


def fetch_notifications() -> str:
    """Fetch notification history."""
    return run_adb_cmd([
        "shell", "dumpsys", "notification"
    ], timeout=60)


def fetch_owner_profile() -> str:
    """Fetch the device owner's profile (Me profile)."""
    return run_adb_cmd([
        "shell", "content", "query",
        "--uri", "content://com.android.contacts/profile"
    ], timeout=30)


# ============================================================================
# PARSING FUNCTIONS
# ============================================================================

def parse_sms(output: str) -> List[Dict]:
    """
    Parse SMS content query output.
    
    Returns list of dicts with fields:
    - _id: Message ID
    - thread_id: Conversation thread
    - address: Phone number
    - date: Timestamp (milliseconds)
    - read: Read status (0/1)
    - type: Message type (1=inbox, 2=sent, 3=draft, 4=outbox, 5=failed)
    - body: Message text
    """
    rows = parse_content_query(output)
    messages = []
    
    for row in rows:
        msg = {
            '_id': row.get('_id', ''),
            'thread_id': row.get('thread_id', ''),
            'address': row.get('address', ''),
            'date': row.get('date', ''),
            'date_sent': row.get('date_sent', ''),
            'read': row.get('read', '0'),
            'type': row.get('type', ''),  # 1=inbox, 2=sent
            'body': row.get('body', ''),
            'seen': row.get('seen', '0'),
            'status': row.get('status', '')
        }
        messages.append(msg)
    
    return messages


def parse_installed_packages(output: str) -> List[Dict]:
    """
    Parse installed packages output.
    
    Returns list of dicts with:
    - package_name: App package identifier
    - apk_path: Location of APK file
    """
    packages = []
    if not output:
        return packages
    
    lines = output.strip().split('\n')
    for line in lines:
        if line.startswith('package:'):
            # Format: package:/path/to/app.apk=com.app.package
            parts = line[8:].split('=')
            if len(parts) == 2:
                packages.append({
                    'apk_path': parts[0].strip(),
                    'package_name': parts[1].strip()
                })
    
    return packages


def parse_wifi_networks(output: str) -> List[Dict]:
    """
    Parse WiFi networks output.
    
    Returns list of dicts with network information.
    """
    networks = []
    if not output:
        return networks
    
    # Simple parsing - extract SSID patterns
    lines = output.split('\n')
    for line in lines:
        if 'SSID' in line or 'ssid' in line:
            networks.append({'raw': line.strip()})
    
    return networks


def parse_calendar_events(output: str) -> List[Dict]:
    """
    Parse calendar events.
    
    Returns list of dicts with:
    - title: Event title
    - description: Event description
    - dtstart: Start time
    - dtend: End time
    - eventLocation: Location
    """
    rows = parse_content_query(output)
    events = []
    
    for row in rows:
        event = {
            '_id': row.get('_id', ''),
            'title': row.get('title', ''),
            'description': row.get('description', ''),
            'eventLocation': row.get('eventLocation', ''),
            'dtstart': row.get('dtstart', ''),
            'dtend': row.get('dtend', ''),
            'allDay': row.get('allDay', ''),
            'organizer': row.get('organizer', ''),
            'hasAlarm': row.get('hasAlarm', '')
        }
        events.append(event)
    
    return events
