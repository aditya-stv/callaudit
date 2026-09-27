# report_generator.py - Android Forensic Auditor Reporting Engine

from google import genai
import os
from datetime import datetime
import pandas as pd
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, Image as RLImage
from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_JUSTIFY
from PIL import Image
import io
import socket
import requests

# Import visualization functions
try:
    from forensic_visualizations import (
        create_duration_histogram,
        create_top_contacts_chart,
        create_behavioral_heatmap,
        create_burner_phone_chart,
        create_sms_activity_chart,
        create_top_sms_contacts_chart,
        create_browser_activity_chart,
        create_app_usage_chart,
        create_calendar_distribution_chart,
    )
    VISUALIZATIONS_AVAILABLE = True
except ImportError:
    VISUALIZATIONS_AVAILABLE = False

# Configure Gemini API from deployment secrets, never source code.
def _get_gemini_api_key():
    key = os.environ.get("GEMINI_API_KEY")
    if key:
        return key

    try:
        import streamlit as st
        return st.secrets.get("GEMINI_API_KEY")
    except Exception:
        return None

# Configure Ollama (Local LLM)
OLLAMA_BASE_URL = "http://localhost:11434"  # Default Ollama endpoint
OLLAMA_MODEL = "llama3"  # Options: llama3, mistral, llama2, etc.

def check_internet_connection():
    """Check if internet connection is available."""
    try:
        # Try to connect to Google's DNS
        socket.create_connection(("8.8.8.8", 53), timeout=3)
        return True
    except OSError:
        return False

def check_ollama_available():
    """Check if Ollama is running locally."""
    try:
        response = requests.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=2)
        return response.status_code == 200
    except Exception:
        return False

def get_available_ai_backend():
    """Determine which AI backend to use based on availability."""
    has_internet = check_internet_connection()
    has_ollama = check_ollama_available()
    
    if has_internet:
        return "gemini"
    elif has_ollama:
        return "ollama"
    else:
        return None

def generate_with_ollama(prompt, model=OLLAMA_MODEL):
    """Generate content using local Ollama LLM."""
    try:
        response = requests.post(
            f"{OLLAMA_BASE_URL}/api/generate",
            json={
                "model": model,
                "prompt": prompt,
                "stream": False
            },
            timeout=120  # 2 minutes timeout for local generation
        )
        
        if response.status_code == 200:
            return response.json().get('response', '')
        else:
            raise Exception(f"Ollama returned status {response.status_code}")
    except Exception as e:
        raise Exception(f"Ollama generation failed: {str(e)}")

def get_gemini_client():
    """Initialize Gemini client with API key."""
    api_key = _get_gemini_api_key()
    if not api_key:
        raise RuntimeError(
            "GEMINI_API_KEY is not configured. Add it to Streamlit Secrets "
            "or the GEMINI_API_KEY environment variable."
        )
    return genai.Client(api_key=api_key)

def generate_finding_summary(finding_type, data, context=""):
    """
    Generate AI-powered summary of forensic findings.
    
    Args:
        finding_type: Type of finding (e.g., 'burner_phone', 'critical_window')
        data: Data dictionary with findings
        context: Additional context
        
    Returns:
        String summary
    """
    try:
        client = get_gemini_client()
        
        prompt = f"""You are a digital forensics expert writing a professional forensic report.
        
Analyze the following {finding_type} finding and provide a concise, professional summary suitable for a forensic investigation report:

Data: {data}
Context: {context}

Provide a 2-3 sentence expert analysis highlighting:
1. What this finding indicates
2. Its significance to the investigation
3. Recommended next steps (if applicable)

Write in formal, technical language appropriate for law enforcement/legal proceedings."""

        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt
        )
        return response.text
        
    except Exception as e:
        return f"AI analysis unavailable: {str(e)}"


def generate_executive_summary(df, forensic_analyses):
    """
    Generate an executive summary focusing on identity and key findings.
    """
    try:
        # Determine which AI backend to use
        backend = get_available_ai_backend()
        
        if backend is None:
            return "**ERROR**: No AI backend available for executive summary generation."
        
        # Get appropriate client
        if backend == "gemini":
            client = get_gemini_client()
        else:
            client = None
        
        # Basic statistics
        total_calls = len(df)
        unique_numbers = df['number'].nunique()
        date_range = f"{df['datetime'].min()} to {df['datetime'].max()}"
        
        prompt = f"""Generate a CONCISE executive summary (3-4 paragraphs) for a forensic investigation.
        
**PRIMARY FOCUS: WHO IS THIS PERSON?**

Analyze the following data and create an executive summary that prioritizes:

1. **Identity Information**: Any confirmed or inferred identity markers (name, email, demographics)
2. **Person Profile**: Age range, gender, occupation, lifestyle indicators
3. **Key Behavioral Patterns**: Notable habits, interests, social patterns
4. **Critical Findings**: Any suspicious or noteworthy forensic findings
5. **Investigative Significance**: What this data tells us about the person

Data Summary:
- Total communications: {total_calls} calls
- Unique contacts: {unique_numbers}
- Period: {date_range}
- Call distribution: {df['call_type'].value_counts().to_dict()}

Forensic Findings: {str(forensic_analyses)[:1000]}

Write in formal, professional language. Lead with identity information if available, then summarize behavioral patterns and key findings. Keep it concise but informative."""
        
        # Generate using appropriate backend
        if backend == "gemini":
            response = client.models.generate_content(
                model='gemini-2.5-flash',
                contents=prompt
            )
            return response.text
        else:  # ollama
            return generate_with_ollama(prompt)
        
    except Exception as e:
        return f"Executive summary generation failed: {str(e)}"


def generate_comprehensive_report(case_info, df, forensic_analyses, device_info=None, full_forensic_data=None):
    """
    Generate a comprehensive forensic report using available AI (Gemini online or Ollama offline).
    """
    try:
        # Determine which AI backend to use
        backend = get_available_ai_backend()
        
        if backend is None:
            return "**ERROR**: No AI backend available. Please ensure either:\n1. Internet connection is available for Gemini API, OR\n2. Ollama is installed and running locally (see setup instructions)"
        
        # Get appropriate client based on backend
        if backend == "gemini":
            client = get_gemini_client()
            status_msg = "Using Gemini AI (Online)"
        else:  # ollama
            client = None  # Ollama uses direct API calls
            status_msg = f"Using Ollama (Offline - Model: {OLLAMA_MODEL})"
        
        # Prepare device info section
        device_section = ""
        if device_info:
            device_section = f"""
**DEVICE INFORMATION:**
- Model: {device_info.get('model', 'Unknown')}
- Brand: {device_info.get('brand', 'Unknown')}
- OS: Android {device_info.get('android_version', 'Unknown')} (SDK {device_info.get('sdk', 'Unknown')})
- Battery: {device_info.get('battery_level', 'Unknown')}
- Uptime: {device_info.get('uptime', 'Unknown')}
"""

        # Prepare expanded data context
        extra_sources_section = ""
        if full_forensic_data:
            sms_data = full_forensic_data.get('sms_data', [])
            browser_searches = full_forensic_data.get('browser_searches', "")
            apps_data = full_forensic_data.get('apps_data', [])
            calendar_events = full_forensic_data.get('calendar_events', [])
            wifi_raw = full_forensic_data.get('wifi_raw', "")
            logs_raw = full_forensic_data.get('logcat_raw', "")
            
            if sms_data:
                sms_df = pd.DataFrame(sms_data)
                extra_sources_section += f"\n**SMS RECONNAISSANCE**:\n- Total: {len(sms_df)}\n- Top Contacts: {sms_df['address'].value_counts().head(5).to_dict()}\n- Recent: {sms_df.head(3)[['address', 'body']].to_dict('records')}\n"
                
                sus_sms = full_forensic_data.get('suspicious_sms')
                if sus_sms is not None and not sus_sms.empty:
                    extra_sources_section += f"- **SUSPICIOUS SMS DETECTED**: {len(sus_sms)} alerts found. Sample: {sus_sms.head(5)[['address', 'score', 'reasons']].to_dict('records')}\n"
            
            if browser_searches:
                extra_sources_section += f"\n**BROWSER HISTORY/SEARCHES**:\n{browser_searches[:2000]}\n"
            
            if apps_data:
                extra_sources_section += f"\n**INSTALLED APPLICATIONS**:\n- Count: {len(apps_data)}\n- Sample: {[app.get('package_name') for app in apps_data[:20]]}\n"
            
            if calendar_events:
                extra_sources_section += f"\n**CALENDAR EVENTS**:\n- Count: {len(calendar_events)}\n- Highlights: {[e.get('title') for e in calendar_events[:10]]}\n"
            
            if wifi_raw:
                extra_sources_section += f"\n**NETWORK ARTIFACTS (WiFi)**:\n{wifi_raw[:1000]}\n"
            
            if logs_raw:
                extra_sources_section += f"\n**SYSTEM LOGS (LOGCAT)**:\n{logs_raw[:1000]}\n"
                sec_logs = full_forensic_data.get('security_logs')
                if sec_logs:
                    extra_sources_section += f"- **CRITICAL LOG ALERTS**: {len(sec_logs)} events flagged. Recent: {sec_logs[:5]}\n"

            sus_apps = full_forensic_data.get('suspicious_apps')
            if sus_apps is not None and not sus_apps.empty:
                extra_sources_section += f"\n**SUSPICIOUS APPLICATIONS**: {len(sus_apps)} targets identified. Types: {sus_apps['findings'].unique().tolist()}\n"
                
            net_anom = full_forensic_data.get('network_anomalies')
            if net_anom:
                extra_sources_section += f"\n**NETWORK/IDENTITY ANOMALIES**: {net_anom}\n"
            
            browser_cats = full_forensic_data.get('browser_categories')
            if browser_cats is not None and not browser_cats.empty:
                extra_sources_section += f"\n**WEB BROWSING DISPOSITION**: {browser_cats['category'].value_counts().to_dict()}\n"
            
            wifi_profs = full_forensic_data.get('wifi_profiles')
            if wifi_profs is not None and not wifi_profs.empty:
                extra_sources_section += f"\n**KNOWN WIFI ENVIRONMENTS**: {wifi_profs['ssid'].tolist()}\n"
            
            bt_pairings = full_forensic_data.get('bluetooth_pairings')
            if bt_pairings:
                extra_sources_section += f"\n**BLUETOOTH HARDWARE LINKS**: {[d['name'] for d in bt_pairings]}\n"

            parsed_usage = full_forensic_data.get('parsed_app_usage')
            if parsed_usage is not None and not parsed_usage.empty:
                extra_sources_section += f"\n**APP USAGE (FOREGROUND)**:\n- Top Focused Apps: {parsed_usage[['package', 'time_display']].head(5).to_dict('records')}\n"

            parsed_traffic = full_forensic_data.get('parsed_net_traffic')
            if parsed_traffic is not None and not parsed_traffic.empty:
                extra_sources_section += f"\n**NETWORK DATA CONSUMPTION**: Top UIDs by Rx/Tx MB: {parsed_traffic[['uid', 'total_mb']].head(5).to_dict('records')}\n"
            
            raw_alerts = full_forensic_data.get('raw_anomaly_alerts')
            if raw_alerts:
                extra_sources_section += f"\n**EXTREME TECHNICAL ANOMALIES**: {len(raw_alerts)} critical alerts found. Examples: {raw_alerts[:5]}\n"

            account_findings = full_forensic_data.get('account_findings')
            if account_findings:
                extra_sources_section += f"\n**ACCOUNT & IDENTITY RISK ASSESSMENT**: {account_findings}\n"
            
            parsed_accounts = full_forensic_data.get('parsed_accounts')
            if parsed_accounts is not None and not parsed_accounts.empty:
                extra_sources_section += f"\n**DIGITAL IDENTITY ECOSYSTEM**: {parsed_accounts['category'].value_counts().to_dict()}\n"

        # Prepare call data summary
        total_calls = len(df)
        unique_numbers = df['number'].nunique()
        date_range = f"{df['datetime'].min()} to {df['datetime'].max()}"
        
        # Build comprehensive prompt with identity focus
        prompt = f"""You are a certified digital forensics examiner writing an official forensic investigation report.
        
Analyze the provided data holistically as part of an **Android Forensic Auditor Examination**. Cross-correlate connectivity patterns, app usage, system logs, and communication artifacts to build a comprehensive suspect profile.

**PRIMARY OBJECTIVE: IDENTIFY THE DEVICE OWNER/USER**

Your primary goal is to determine WHO this person is by analyzing all available evidence. Focus on:

1. **IDENTITY CONFIRMATION** - Extract definitive identity markers:
   - Full name from accounts (Google, social media, email addresses)
   - Phone number ownership and registration details
   - Email addresses and their associated services
   - Profile information from owner/contact data
   - Account usernames that may reveal real names

2. **IDENTITY INFERENCE** - Make educated guesses based on patterns:
   - Gender indicators (app usage, communication style, account types)
   - Age range (based on apps, social media usage, communication patterns)
   - Occupation/profession (work-related apps, calendar events, communication times)
   - Location/residence (WiFi networks, frequently visited places, timezone patterns)
   - Education level (apps used, writing style in SMS, interests)
   - Relationship status (dating apps, communication patterns, contacts)

3. **BEHAVIORAL PROFILING** - Describe the person's lifestyle:
   - Daily routine and activity patterns
   - Social habits (night owl vs. early bird, social vs. private)
   - Interests and hobbies (based on apps, browsing, calendar)
   - Financial status indicators (banking apps, shopping patterns)
   - Technology literacy level
   - Privacy consciousness (use of encrypted apps, VPNs, etc.)

4. **SOCIAL NETWORK ANALYSIS** - Map their relationships:
   - Key contacts and their likely relationships (family, friends, colleagues)
   - Communication frequency patterns indicating close relationships
   - Social circle composition
   - Suspicious or unusual relationships

5. **DIGITAL FOOTPRINT SUMMARY**:
   - Primary platforms and services used
   - Digital identity across different services
   - Account ecosystem (Google, Apple, social media, financial)
   - Trace the person's online presence

**CRITICAL INSTRUCTIONS:**
- Clearly mark information as either **[CONFIRMED]** (directly extracted from data) or **[INFERRED]** (educated guess based on patterns)
- When inferring, explain your reasoning
- Cross-reference multiple data sources to validate findings
- Look for contradictions or suspicious discrepancies
- Prioritize identity information in your report
- If you cannot determine something, state that explicitly

 CASE INFORMATION:
 Case Number: {case_info.get('case_number', 'N/A')}
 Investigator: {case_info.get('investigator', 'N/A')}
 Device Owner/Suspect: {case_info.get('device_owner', 'Unknown')}
 Analysis Date: {case_info.get('analysis_date', 'N/A')}
 Classification: {case_info.get('classification', 'N/A')}

{device_section}

{extra_sources_section}

CALL LOG SUMMARY:
- Records: {total_calls}
- Unique Numbers: {unique_numbers}
- Date Range: {date_range}
- Distribution: {df['call_type'].value_counts().to_dict()}

FORENSIC ANALYSES PERFORMED (ALGORITHMIC):
{format_analyses_for_prompt(forensic_analyses)}

FORMATTING REQUIREMENTS:
- Use MARKDOWN format (## for headings, ### for subheadings, **bold**, - for bullets)
- Use inline HTML color spans for findings:
  * <span style="color: #dc3545;">text</span> for CRITICAL findings (red)
  * <span style="color: #fd7e14;">text</span> for WARNINGS (orange)
  * <span style="color: #28a745;">text</span> for POSITIVE findings (green)
  * <span style="color: #007bff;">text</span> for INFORMATIONAL items (blue)
- Use markdown tables (| col1 | col2 |) for structured data
- Keep color spans SHORT - only wrap keywords or critical phrases
- Use [CONFIRMED] and [INFERRED] tags to distinguish fact from analysis

REPORT STRUCTURE:
## 1. EXECUTIVE SUMMARY
## 2. IDENTITY PROFILE (WHO IS THIS PERSON?)
   ### 2.1 Confirmed Identity Information
   ### 2.2 Inferred Demographic & Lifestyle Profile
   ### 2.3 Digital Footprint Overview
## 3. DEVICE & METHODOLOGY
## 4. COMMUNICATION ANALYSIS (Calls & SMS)
## 5. SOCIAL NETWORK MAPPING (Key Contacts & Relationships)
## 6. DIGITAL BEHAVIOR ANALYSIS (Apps, Browsing, Usage Patterns)
## 7. TEMPORAL & SPATIAL ARTIFACTS (Calendar, WiFi, Location Indicators)
## 8. SECURITY & PRIVACY ASSESSMENT
## 9. CONCLUSIONS & INVESTIGATIVE LEADS (color-coded by priority)

Write in formal, technical language. Maintain objectivity while being thorough in identity analysis. Highlight anomalies and suspicious patterns."""

        # Generate report using appropriate backend
        if backend == "gemini":
            response = client.models.generate_content(
                model='gemini-2.5-flash',
                contents=prompt
            )
            report = response.text
        else:  # ollama
            report = generate_with_ollama(prompt)
        
        # Prepend status message
        return f"**AI Backend Status**: {status_msg}\n\n---\n\n{report}"
        
    except Exception as e:
        return f"Error generating AI report: {str(e)}\n\nPlease review forensic analyses manually."


def format_analyses_for_prompt(analyses):
    """Format forensic analyses for AI prompt."""
    formatted = ""
    
    if 'burner_phones' in analyses and not analyses['burner_phones'].empty:
        formatted += f"\nBURNER PHONE DETECTION:\n"
        formatted += f"Detected: {len(analyses['burner_phones'])} potential burner phones\n"
        formatted += f"Top suspects: {analyses['burner_phones']['number'].head(3).tolist()}\n"
    
    if 'critical_window' in analyses:
        cw = analyses['critical_window']
        formatted += f"\nCRITICAL TIME WINDOW:\n"
        formatted += f"Before incident: {cw.get('before', {}).get('count', 0)} calls\n"
        formatted += f"After incident: {cw.get('after', {}).get('count', 0)} calls\n"
    
    if 'behavioral_changes' in analyses:
        bc = analyses['behavioral_changes']
        if 'first_period' in bc:
            formatted += f"\nBEHAVIORAL CHANGES:\n"
            formatted += f"Early period: {bc['first_period']['calls_per_day']:.1f} calls/day\n"
            formatted += f"Recent period: {bc['last_period']['calls_per_day']:.1f} calls/day\n"
    
    if 'activity_bursts' in analyses and not analyses['activity_bursts'].empty:
        formatted += f"\nACTIVITY BURSTS:\n"
        formatted += f"Detected: {len(analyses['activity_bursts'])} unusual activity spikes\n"
    
    if 'key_contacts' in analyses and not analyses['key_contacts'].empty:
        formatted += f"\nKEY CONTACTS:\n"
        top_5 = analyses['key_contacts'].head(5)
        formatted += f"Most important contacts: {top_5['number'].tolist()}\n"
    
    return formatted


def generate_pdf_report(report_text, case_info, output_path, df=None, full_forensic_data=None):
    """
    Generate a professional PDF forensic report.
    """
    import re
    
    # Generate visualization images if df is provided
    chart_images = {}
    if df is not None and VISUALIZATIONS_AVAILABLE and not df.empty:
        try:
            # Generate charts
            charts_to_generate = {
                'timeline': create_timeline_chart(df),
                'call_types': create_call_type_distribution(df),
                'hourly': create_hourly_activity_chart(df),
                'duration': create_duration_histogram(df),
                'top_contacts': create_top_contacts_chart(df, top_n=10),
                'heatmap': create_behavioral_heatmap(df),
            }
            
            # Add extra charts if full_forensic_data is available
            if full_forensic_data:
                sms_data = full_forensic_data.get('sms_data')
                if sms_data:
                    sms_df = pd.DataFrame(sms_data)
                    charts_to_generate['sms_timeline'] = create_sms_activity_chart(sms_df)
                    charts_to_generate['sms_contacts'] = create_top_sms_contacts_chart(sms_df)
                    charts_to_generate['sms_hourly'] = create_sms_hourly_chart(sms_df)
                    charts_to_generate['sms_length'] = create_sms_length_dist(sms_df)
                
                browser_searches = full_forensic_data.get('browser_searches')
                if browser_searches:
                    charts_to_generate['browser_search'] = create_browser_activity_chart(browser_searches)
                    browser_cats = full_forensic_data.get('browser_categories')
                    if browser_cats is not None:
                        charts_to_generate['browser_domains'] = create_browser_domain_pie(browser_cats)
                
                wifi_profs = full_forensic_data.get('wifi_profiles')
                if wifi_profs is not None and not wifi_profs.empty:
                    charts_to_generate['wifi_freq'] = create_wifi_frequency_chart(wifi_profs)
                
                bt_pairings = full_forensic_data.get('bluetooth_pairings')
                if bt_pairings:
                    charts_to_generate['bluetooth_cats'] = create_bluetooth_category_chart(bt_pairings)

                app_usage = full_forensic_data.get('app_usage_raw')
                if app_usage:
                    charts_to_generate['app_usage'] = create_app_usage_chart(app_usage)
                    parsed_usage = full_forensic_data.get('parsed_app_usage')
                    if parsed_usage is not None:
                        charts_to_generate['usage_dist'] = create_app_foreground_pie(parsed_usage)
                
                net_traffic = full_forensic_data.get('parsed_net_traffic')
                if net_traffic is not None:
                    charts_to_generate['traffic_bar'] = create_data_usage_bar(net_traffic)
                    charts_to_generate['tx_rx_scatter'] = create_tx_rx_scatter(net_traffic)
                
                suspicious_apps = full_forensic_data.get('suspicious_apps')
                if suspicious_apps is not None:
                    charts_to_generate['app_categories'] = create_app_category_chart(suspicious_apps)
                
                parsed_accounts = full_forensic_data.get('parsed_accounts')
                if parsed_accounts is not None:
                    charts_to_generate['account_dist'] = create_account_distribution_pie(parsed_accounts)
                
                log_sec = full_forensic_data.get('security_logs')
                if log_sec:
                    charts_to_generate['log_intensity'] = create_log_intensity_chart(log_sec)
                
                calendar_events = full_forensic_data.get('calendar_events')
                if calendar_events:
                    cal_df = pd.DataFrame(calendar_events)
                    charts_to_generate['calendar_dist'] = create_calendar_distribution_chart(cal_df)
            
            # Convert Plotly figures to images
            for chart_name, fig in charts_to_generate.items():
                if fig is not None:
                    try:
                        # Save as PNG bytes
                        img_bytes = fig.to_image(format="png", width=700, height=400)
                        chart_images[chart_name] = img_bytes
                    except Exception as e:
                        print(f"Error converting {chart_name} to image: {e}")
        except Exception as e:
            print(f"Error generating charts: {e}")
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter,
                           rightMargin=72, leftMargin=72,
                           topMargin=72, bottomMargin=18)
    
    # Container for the 'Flowable' objects
    elements = []
    
    # Define styles
    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name='Justify', alignment=TA_JUSTIFY, fontSize=10, leading=14))
    styles.add(ParagraphStyle(name='CaseHeader', fontSize=14, textColor=colors.HexColor('#1f4788'), 
                             spaceAfter=12, fontName='Helvetica-Bold'))
    styles.add(ParagraphStyle(name='ReportHeading2', fontSize=13, textColor=colors.HexColor('#1f4788'),
                             spaceAfter=10, spaceBefore=10, fontName='Helvetica-Bold'))
    
    # Title
    title_style = ParagraphStyle(
        'CustomTitle',
        parent=styles['Heading1'],
        fontSize=18,
        textColor=colors.HexColor('#1f4788'),
        spaceAfter=30,
        alignment=TA_CENTER,
        fontName='Helvetica-Bold'
    )
    
    # Header
    elements.append(Paragraph("ANDROID FORENSIC AUDITOR INVESTIGATION REPORT", title_style))
    elements.append(Spacer(1, 0.3*inch))
    
    # Case Information Table
    case_data = [
        ['Case Number:', case_info.get('case_number', 'N/A')],
        ['Investigator:', case_info.get('investigator', 'N/A')],
        ['Analysis Date:', case_info.get('analysis_date', datetime.now().strftime('%Y-%m-%d'))],
        ['Device Owner:', case_info.get('device_owner', 'Unknown')],
        ['Classification:', case_info.get('classification', 'CONFIDENTIAL')]
    ]
    
    case_table = Table(case_data, colWidths=[2*inch, 4*inch])
    case_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#e8eef7')),
        ('TEXTCOLOR', (0, 0), (-1, -1), colors.black),
        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
        ('FONTSIZE', (0, 0), (-1, -1), 10),
        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('LEFTPADDING', (0, 0), (-1, -1), 12),
    ]))
    
    elements.append(case_table)
    elements.append(Spacer(1, 0.5*inch))
    
    # Helper function to convert HTML color spans to reportlab format
    def convert_color_spans(text):
        """Convert HTML color spans to reportlab font color tags"""
        # Convert color spans to reportlab format
        text = re.sub(r'<span style="color:\s*#([0-9a-fA-F]{6});">(.*?)</span>', 
                     r'<font color="#\1">\2</font>', text)
        return text
    
    # Helper function to parse markdown tables
    def parse_markdown_table(lines):
        """Parse markdown table lines and return reportlab Table object"""
        if len(lines) < 2:
            return None
        
        # Parse table rows
        rows = []
        for line in lines:
            if '|' in line:
                # Split by | and clean up
                cells = [cell.strip() for cell in line.split('|') if cell.strip()]
                # Skip separator lines (like |---|---|)
                if cells and not all('-' in cell for cell in cells):
                    rows.append(cells)
        
        if not rows:
            return None
        
        # Create table with styling
        table = Table(rows)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#e8eef7')),  # Header background
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.HexColor('#1f4788')),   # Header text
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 9),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('LEFTPADDING', (0, 0), (-1, -1), 8),
            ('RIGHTPADDING', (0, 0), (-1, -1), 8),
        ]))
        return table
    
    # Report Content - process line by line with color and table support
    lines = report_text.split('\n')
    i = 0
    while i < len(lines):
        line = lines[i]
        
        if line.strip():
            # Check for markdown table start
            if line.startswith('|') and i + 1 < len(lines):
                # Collect all table lines
                table_lines = []
                while i < len(lines) and lines[i].strip().startswith('|'):
                    table_lines.append(lines[i])
                    i += 1
                
                # Parse and add table
                table = parse_markdown_table(table_lines)
                if table:
                    elements.append(table)
                    elements.append(Spacer(1, 0.2*inch))
                continue
            
            # Check for markdown headings
            if line.startswith('## '):
                # Main heading
                heading_text = convert_color_spans(line.replace('## ', ''))
                elements.append(Paragraph(heading_text, styles['ReportHeading2']))
            elif line.startswith('### '):
                # Subheading
                subheading_text = convert_color_spans(line.replace('### ', ''))
                elements.append(Paragraph(subheading_text, styles['CaseHeader']))
            else:
                # Regular paragraph - preserve colors and convert markdown bold
                clean_line = convert_color_spans(line)
                
                # Convert markdown bold to reportlab bold
                # Handle ** for bold - simple replacement
                parts = clean_line.split('**')
                if len(parts) > 1:
                    clean_line = ''
                    for idx, part in enumerate(parts):
                        if idx % 2 == 1:  # Odd indices are bold
                            clean_line += f'<b>{part}</b>'
                        else:
                            clean_line += part
                
                try:
                    elements.append(Paragraph(clean_line, styles['Justify']))
                    elements.append(Spacer(1, 0.1*inch))
                except Exception as e:
                    # If paragraph fails, add plain text without formatting
                    plain_text = re.sub(r'<[^>]+>', '', line.strip())
                    elements.append(Paragraph(plain_text, styles['Justify']))
                    elements.append(Spacer(1, 0.1*inch))
        
        i += 1
    
    # Add visualization charts if available
    if chart_images:
        elements.append(PageBreak())
        elements.append(Paragraph("FORENSIC DATA VISUALIZATIONS", styles['ReportHeading2']))
        elements.append(Spacer(1, 0.3*inch))
        
        chart_titles = {
            'timeline': 'Communication Timeline',
            'call_types': 'Call Type Distribution',
            'hourly': 'Hourly Activity Pattern',
            'duration': 'Call Duration Distribution',
            'top_contacts': 'Top 10 Contacts',
            'heatmap': 'Activity Heatmap (Day × Hour)',
            'sms_timeline': 'SMS Communication Timeline',
            'sms_contacts': 'Top SMS Interlocutors',
            'sms_hourly': 'SMS Hourly Distribution',
            'sms_length': 'SMS Message Length Profile',
            'browser_search': 'Browser Search Activity',
            'browser_domains': 'Web Domain Category Distribution',
            'wifi_freq': 'Configured WiFi Networks Profile',
            'bluetooth_cats': 'Paired Bluetooth Device Types',
            'app_usage': 'Application Usage Distribution',
            'usage_dist': 'App Foreground Time Distribution',
            'traffic_bar': 'Top Apps by Data Consumption (MB)',
            'tx_rx_scatter': 'Technical Exfiltration Analysis (Tx vs Rx)',
            'app_categories': 'Forensic Application categories',
            'account_dist': 'Digital Identity Ecosystem Profile',
            'log_intensity': 'Security Log Event Timeline',
            'calendar_dist': 'Calendar Activity Categories'
        }
        
        for chart_name, img_bytes in chart_images.items():
            try:
                # Create PIL Image from bytes
                img = Image.open(io.BytesIO(img_bytes))
                
                # Save to temporary BytesIO
                img_buffer = io.BytesIO()
                img.save(img_buffer, format='PNG')
                img_buffer.seek(0)
                
                # Add title
                title = chart_titles.get(chart_name, chart_name.title())
                elements.append(Paragraph(title, styles['CaseHeader']))
                elements.append(Spacer(1, 0.1*inch))
                
                # Add image (resize to fit page)
                rl_image = RLImage(img_buffer, width=6*inch, height=3.5*inch)
                elements.append(rl_image)
                elements.append(Spacer(1, 0.3*inch))
                
            except Exception as e:
                print(f"Error adding {chart_name} to PDF: {e}")
    
    
    # Footer
    elements.append(PageBreak())
    footer_text = f"""
    <para alignment="center">
    <b>CONFIDENTIAL - LAW ENFORCEMENT SENSITIVE</b><br/>
    This report contains confidential information and is intended solely for official use.<br/>
    Unauthorized disclosure is prohibited.<br/><br/>
    Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br/>
    Report ID: {case_info.get('case_number', 'UNKNOWN')}-{datetime.now().strftime('%Y%m%d')}
    </para>
    """
    elements.append(Paragraph(footer_text, styles['Normal']))
    
    # Build PDF
    doc.build(elements)
    
    # Get PDF data
    pdf_data = buffer.getvalue()
    buffer.close()
    
    # Write to file
    with open(output_path, 'wb') as f:
        f.write(pdf_data)
    
    return pdf_data


def generate_executive_summary(df, forensic_analyses):
    """Generate executive summary using Gemini AI."""
    try:
        client = get_gemini_client()
        
        prompt = f"""As a senior digital forensics examiner, create a concise executive summary for law enforcement leadership.

Data Overview:
- {len(df)} total call records analyzed
- {df['number'].nunique()} unique contacts
- Time span: {(df['datetime'].max() - df['datetime'].min()).days} days

Key Findings Summary:
{format_analyses_for_prompt(forensic_analyses)}

Create a 4-6 sentence executive summary that:
1. States the scope of analysis
2. Highlights the 2-3 most significant findings
3. Provides an overall risk/threat assessment
4. Recommends immediate next steps

Use clear, non-technical language suitable for senior management and prosecutors."""

        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt
        )
        return response.text
        
    except Exception as e:
        return f"Executive summary generation failed: {str(e)}"


def generate_timeline_narrative(timeline_events):
    """Generate narrative description of timeline using AI."""
    try:
        client = get_gemini_client()
        
        prompt = f"""You are a digital forensics analyst creating a timeline narrative for an investigation report.

Timeline Events:
{timeline_events}

Create a chronological narrative that:
1. Describes the sequence of communication events
2. Highlights significant patterns or anomalies
3. Connects events that may be related
4. Uses precise timestamps

Write in past tense, formal tone. 3-5 sentences maximum."""

        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt
        )
        return response.text
        
    except Exception as e:
        return "Timeline narrative unavailable."


def generate_suspect_profile(contact_data, call_patterns):
    """Generate AI-powered suspect behavioral profile."""
    try:
        client = get_gemini_client()
        
        prompt = f"""As a forensic behavioral analyst, create a brief communication pattern profile.

Contact Behavior Data:
- Total communications: {contact_data.get('total_calls', 0)}
- Communication frequency: {contact_data.get('calls_per_day', 0):.1f} per day
- Preferred hours: {contact_data.get('peak_hours', [])}
- Call duration patterns: {contact_data.get('avg_duration', 0):.0f}s average
- Contact diversity: {contact_data.get('unique_contacts', 0)} individuals

Observed Patterns:
{call_patterns}

Provide a 3-4 sentence behavioral assessment including:
1. Communication habits and patterns
2. Social network characteristics
3. Any behavioral red flags
4. Investigative significance

Use professional forensic psychology terminology."""

        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt
        )
        return response.text
        
    except Exception as e:
        return "Profile generation unavailable."
