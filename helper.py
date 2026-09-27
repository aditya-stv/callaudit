# helper.py
import subprocess
import re
import os
import shutil
from typing import List

def _resolve_adb_path() -> str:
    """Auto-detect adb path across different machines and environments."""
    # 1. Check custom environment variable
    env_adb = os.environ.get("ADB_PATH")
    if env_adb and os.path.exists(env_adb):
        return env_adb

    # 2. Check if 'adb' is available in system PATH
    which_adb = shutil.which("adb")
    if which_adb:
        return which_adb

    # 3. Check common default installation locations on Windows
    candidate_paths = [
        r"C:\platform-tools\adb.exe",
        os.path.expandvars(r"%LOCALAPPDATA%\Android\Sdk\platform-tools\adb.exe"),
        os.path.expandvars(r"%USERPROFILE%\AppData\Local\Android\Sdk\platform-tools\adb.exe"),
        r"C:\Program Files\Android\platform-tools\adb.exe",
        r"D:\platform-tools\adb.exe",
    ]
    for path in candidate_paths:
        if os.path.exists(path):
            return path

    # Fallback to "adb" expecting it in PATH or giving clear guidance
    return r"C:\platform-tools\adb.exe"

# Set resolved ADB path
ADB_PATH = _resolve_adb_path()


def run_adb_cmd(cmd_args: List[str], timeout: int = 30) -> str:
    """
    Run adb using ADB_PATH. cmd_args: list like ["devices"] or ["shell", "content", "query", ...]
    Returns decoded stdout or raises RuntimeError on failure.
    """
    global ADB_PATH
    # If currently cached ADB_PATH doesn't exist, re-resolve
    if not os.path.exists(ADB_PATH) and shutil.which("adb"):
        ADB_PATH = shutil.which("adb")

    cmd = [ADB_PATH] + cmd_args
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT, timeout=timeout)
        return out.decode(errors="ignore")
    except subprocess.CalledProcessError as e:
        out = e.output.decode(errors="ignore") if hasattr(e, "output") else str(e)
        raise RuntimeError(f"ADB command failed:\n{out}")
    except FileNotFoundError:
        raise RuntimeError(
            f"ADB not found at '{ADB_PATH}'.\n"
            "Please ensure Android SDK platform-tools is installed.\n"
            "You can:\n"
            "1. Download platform-tools from: https://developer.android.com/tools/releases/platform-tools\n"
            "2. Extract it to 'C:\\platform-tools' (so 'C:\\platform-tools\\adb.exe' exists)\n"
            "3. Or add its folder to your system PATH environment variable."
        )
    except Exception as e:
        raise RuntimeError(f"Failed to run adb command: {e}")


def adb_devices() -> str:
    """Return output of `adb devices` for diagnostics."""
    return run_adb_cmd(["devices"])


def fetch_call_log_raw() -> str:
    """Fetch raw call log using content provider query."""
    return run_adb_cmd(["shell", "content", "query", "--uri", "content://call_log/calls"], timeout=60)


def fetch_contacts_raw() -> str:
    """Fetch raw contacts using content provider query - tries multiple approaches."""
    # Try the phone data provider first (most reliable)
    try:
        result = run_adb_cmd([
            "shell", "content", "query",
            "--uri", "content://com.android.contacts/data",
            "--projection", "data1:display_name"
        ], timeout=60)
        if result and "Row:" in result:
            return result
    except Exception:
        pass
    
    # Fallback to simpler query
    return run_adb_cmd([
        "shell", "content", "query",
        "--uri", "content://com.android.contacts/data/phones"
    ], timeout=60)


# --- Device info ---
def fetch_device_props() -> str:
    """Return the raw output of `adb shell getprop`."""
    return run_adb_cmd(["shell", "getprop"], timeout=20)


def fetch_battery() -> str:
    """Return the raw output of `adb shell dumpsys battery`."""
    return run_adb_cmd(["shell", "dumpsys", "battery"], timeout=20)


def fetch_meminfo() -> str:
    """Return the raw output of `adb shell dumpsys meminfo all`."""
    return run_adb_cmd(["shell", "dumpsys", "meminfo", "all"], timeout=30)


def fetch_uptime() -> str:
    """Return the raw output of `adb shell uptime`."""
    return run_adb_cmd(["shell", "uptime"], timeout=10)


def parse_content_query(output: str) -> List[dict]:
    """
    Parse output from `adb shell content query --uri ...` where rows look like:
      Row: 0 formatted_number=NULL, duration=142, ..., number=+917860441123, ..., type=1, ...
    Returns a list of dicts (one dict per Row).
    """
    rows = []
    if not output:
        return rows

    # Split into blocks by "Row: <n>"
    parts = re.split(r'\bRow:\s*\d+\b', output)
    for part in parts[1:]:
        record = {}
        # normalize spaces and remove leading/trailing commas
        text = part.replace("\n", " ").strip()
        text = text.strip(", ").rstrip(",")
        if not text:
            continue

        # Prefer comma-separated tokens (sample format). Fallback to whitespace tokens containing '='.
        tokens = [t.strip() for t in text.split(",") if t.strip()]
        if len(tokens) == 1:
            tokens = [t for t in re.split(r'\s+', text) if '=' in t]

        for token in tokens:
            token = token.strip().strip(",")
            if "=" not in token:
                continue
            k, v = token.split("=", 1)
            k = k.strip().strip(",")
            v = v.strip().strip(",")
            # treat explicit NULL as empty string
            if v.upper() == "NULL":
                v = ""
            record[k] = v

        if record:
            rows.append(record)

    return rows


def normalize_phone_number(number: str) -> str:
    """
    Normalize phone number to ensure consistent matching.
    Removes all non-digit characters and handles country codes.
    
    Args:
        number: Raw phone number string
        
    Returns:
        Normalized phone number with only digits
    """
    if not number:
        return ""
    
    # Remove all non-digit characters
    digits_only = ''.join(ch for ch in str(number) if ch.isdigit())
    
    # Handle empty result
    if not digits_only:
        return ""
    
    # For Indian numbers, normalize to 10 digits (remove country code 91)
    # This handles: +91XXXXXXXXXX, 91XXXXXXXXXX, XXXXXXXXXX
    if len(digits_only) > 10:
        # If it starts with 91 and has more than 10 digits, it's likely +91 prefix
        if digits_only.startswith('91') and len(digits_only) == 12:
            return digits_only[2:]  # Remove 91 prefix, keep last 10 digits
        # If it starts with other country codes, try to extract last 10 digits
        elif len(digits_only) >= 10:
            return digits_only[-10:]  # Take last 10 digits
    
    return digits_only


def parse_contacts(output: str) -> dict:
    """
    Parse contacts content query output and return a dict mapping phone numbers to contact names.
    Handles multiple field name variations across different Android versions.
    
    Returns:
        dict: {normalized_phone_number: contact_name}
    """
    contacts = {}
    if not output:
        return contacts
    
    rows = parse_content_query(output)
    
    for row in rows:
        # Extract phone number - try all possible field names
        number = None
        for field in ["data1", "number", "normalized_number", "data", "phone_number"]:
            if field in row and row[field] and row[field].strip():
                number = row[field]
                break
        
        # Extract contact name - try all possible field names
        name = None
        for field in ["display_name", "name", "data2", "contact_name", "formatted_name"]:
            if field in row and row[field] and row[field].strip():
                name = row[field]
                break
        
        # If we have a number but no name, try to find the name from other rows with same contact_id
        # (Sometimes Android separates data across multiple rows)
        if number and not name:
            # Try looking for display_name in the same row under different keys
            for key, value in row.items():
                if 'name' in key.lower() and value and value.strip() and value.upper() != 'NULL':
                    name = value
                    break
        
        # Only add if we have both number and name
        if number and name:
            # Normalize the number for consistent matching
            normalized = normalize_phone_number(number)
            if normalized and name.upper() != 'NULL':
                # If this number already exists, keep the first name (or merge)
                if normalized not in contacts:
                    contacts[normalized] = name
    
    return contacts
